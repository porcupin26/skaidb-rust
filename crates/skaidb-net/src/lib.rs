//! Shared TLS/plaintext transport plumbing for skaidb.
//!
//! One place for certificate loading, rustls config building, and the
//! `Stream`/`Conn` byte-stream abstraction — used by internode transport
//! (`skaidb-cluster`), the client-facing servers (`skaidb-server`), and the
//! driver + shell (`skaidb-driver`, `skaidb-cli`). Keeping cert loading and
//! verification in ONE crate avoids divergent security-critical code paths.
//!
//! Everything here is blocking/synchronous rustls (`StreamOwned`), matching
//! skaidb's thread-per-connection servers — no async runtime.

use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};

/// Install the process-wide ring crypto provider (idempotent). Call before
/// building any rustls config.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// A byte stream: plaintext TCP, or TLS (client or server side) over TCP.
/// `Read + Write`, so the framing/RPC/HTTP layers above are transport-agnostic.
pub enum Stream {
    Plain(TcpStream),
    ClientTls(Box<StreamOwned<ClientConnection, TcpStream>>),
    ServerTls(Box<StreamOwned<ServerConnection, TcpStream>>),
}

impl Stream {
    /// A stable label for logging / status (`plain`/`client-tls`/`server-tls`).
    pub fn kind(&self) -> &'static str {
        match self {
            Stream::Plain(_) => "plain",
            Stream::ClientTls(_) => "client-tls",
            Stream::ServerTls(_) => "server-tls",
        }
    }

    /// Whether this stream is TLS-encrypted.
    pub fn is_tls(&self) -> bool {
        !matches!(self, Stream::Plain(_))
    }

    /// The peer address, if the underlying TCP socket exposes one.
    pub fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            Stream::Plain(s) => s.peer_addr().ok(),
            Stream::ClientTls(s) => s.get_ref().peer_addr().ok(),
            Stream::ServerTls(s) => s.get_ref().peer_addr().ok(),
        }
    }

    /// A second handle on the underlying TCP socket, for LIVENESS PROBING
    /// only — never for reading data.
    ///
    /// `try_clone` dups the descriptor, so both handles share one open file
    /// description: socket options and status flags (`O_NONBLOCK`!) set on
    /// either are visible on the other. A prober must therefore restore what
    /// it changes and must not overlap the owning thread's reads — see
    /// `queries::ConnProbe`, which serializes both against a mutex. For TLS
    /// this is the RAW socket: the bytes are ciphertext, which is exactly
    /// right for probing, since end-of-stream is a TCP-level fact.
    pub fn probe_socket(&self) -> io::Result<TcpStream> {
        match self {
            Stream::Plain(s) => s.try_clone(),
            Stream::ClientTls(s) => s.get_ref().try_clone(),
            Stream::ServerTls(s) => s.get_ref().try_clone(),
        }
    }

    /// The server's end-entity certificate (DER) as this CLIENT-side
    /// stream verified it — `None` on plaintext or the server side.
    pub fn peer_certificate_der(&self) -> Option<Vec<u8>> {
        match self {
            Stream::ClientTls(s) => s.conn.peer_certificates()?.first().map(|c| c.to_vec()),
            _ => None,
        }
    }

    /// Set (or with `None` clear) the read timeout on the underlying socket.
    ///
    /// Callers use this to bound a phase rather than a connection — arm it
    /// for a handshake, clear it once the peer is authenticated — so an
    /// idle-but-legitimate session is never dropped for being quiet.
    pub fn set_read_timeout(&self, dur: Option<std::time::Duration>) -> io::Result<()> {
        match self {
            Stream::Plain(s) => s.set_read_timeout(dur),
            Stream::ClientTls(s) => s.get_ref().set_read_timeout(dur),
            Stream::ServerTls(s) => s.get_ref().set_read_timeout(dur),
        }
    }
}

impl fmt::Debug for Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Stream").field(&self.kind()).finish()
    }
}

impl Drop for Stream {
    /// Send a TLS `close_notify` and flush before the socket closes, so the
    /// peer reads a clean end-of-stream instead of an "unexpected EOF" (which
    /// rustls treats as an error — it otherwise breaks HTTP `Connection: close`
    /// responses over TLS). No-op for plaintext.
    fn drop(&mut self) {
        match self {
            Stream::ServerTls(s) => {
                s.conn.send_close_notify();
                let _ = s.flush();
            }
            Stream::ClientTls(s) => {
                s.conn.send_close_notify();
                let _ = s.flush();
            }
            Stream::Plain(_) => {}
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::ClientTls(s) => s.read(buf),
            Stream::ServerTls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::ClientTls(s) => s.write(buf),
            Stream::ServerTls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::ClientTls(s) => s.flush(),
            Stream::ServerTls(s) => s.flush(),
        }
    }
}

/// A connection with a buffered read side (so a length-prefixed frame read
/// costs one syscall, not two) and a direct write side. `Read + Write` — a
/// single object usable for both directions, which TLS requires (a rustls
/// session can't be `try_clone`d into separate reader/writer handles).
pub struct Conn {
    stream: BufReader<Stream>,
}

impl Conn {
    pub fn new(stream: Stream) -> Conn {
        Conn {
            stream: BufReader::new(stream),
        }
    }

    /// The buffered read side (for readers that want the `BufRead` API).
    pub fn reader(&mut self) -> &mut BufReader<Stream> {
        &mut self.stream
    }

    /// The underlying stream, for writes (bypasses the read buffer).
    pub fn writer(&mut self) -> &mut Stream {
        self.stream.get_mut()
    }

    pub fn kind(&self) -> &'static str {
        self.stream.get_ref().kind()
    }
    pub fn is_tls(&self) -> bool {
        self.stream.get_ref().is_tls()
    }
    pub fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.stream.get_ref().peer_addr()
    }
    /// See [`Stream::probe_socket`].
    pub fn probe_socket(&self) -> io::Result<TcpStream> {
        self.stream.get_ref().probe_socket()
    }
    /// See [`Stream::set_read_timeout`].
    pub fn set_read_timeout(&self, dur: Option<std::time::Duration>) -> io::Result<()> {
        self.stream.get_ref().set_read_timeout(dur)
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl io::BufRead for Conn {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.stream.fill_buf()
    }
    fn consume(&mut self, amt: usize) {
        self.stream.consume(amt)
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.get_mut().write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.get_mut().flush()
    }
}

impl fmt::Debug for Conn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Conn").field(&self.kind()).finish()
    }
}

// --- Channel binding (RFC 5929) ---

/// The `tls-server-end-point` channel-binding data for a server
/// certificate (DER): the literal prefix followed by the certificate's
/// hash — SHA-256, or SHA-384/SHA-512 when the certificate's own signature
/// algorithm uses one of those (RFC 5929 §4.1; MD5/SHA-1 upgrade to
/// SHA-256). Both ends of a GSSAPI handshake inside TLS compute this from
/// the same certificate, so a token replayed to another server does not
/// verify.
pub fn tls_server_end_point(cert_der: &[u8]) -> Vec<u8> {
    let alg = match signature_hash(cert_der) {
        SigHash::Sha384 => &ring::digest::SHA384,
        SigHash::Sha512 => &ring::digest::SHA512,
        SigHash::Sha256 => &ring::digest::SHA256,
    };
    let mut out = b"tls-server-end-point:".to_vec();
    out.extend_from_slice(ring::digest::digest(alg, cert_der).as_ref());
    out
}

enum SigHash {
    Sha256,
    Sha384,
    Sha512,
}

/// The hash of a certificate's outer `signatureAlgorithm` OID, defaulting
/// to SHA-256 for anything unrecognised (a defensive DER walk — never a
/// panic).
fn signature_hash(der: &[u8]) -> SigHash {
    #[allow(clippy::type_complexity)]
    fn tlv(b: &[u8]) -> Option<((u8, &[u8]), &[u8])> {
        let tag = *b.first()?;
        let first = *b.get(1)?;
        let (len, hdr) = if first & 0x80 == 0 {
            (usize::from(first), 2)
        } else {
            let n = usize::from(first & 0x7F);
            if n == 0 || n > 4 {
                return None;
            }
            let mut len = 0usize;
            for i in 0..n {
                len = (len << 8) | usize::from(*b.get(2 + i)?);
            }
            (len, 2 + n)
        };
        let end = hdr.checked_add(len)?;
        if end > b.len() {
            return None;
        }
        Some(((tag, &b[hdr..end]), &b[end..]))
    }
    let oid = (|| {
        let ((_, cert), _) = tlv(der)?;
        let ((_, _tbs), rest) = tlv(cert)?;
        let ((_, alg), _) = tlv(rest)?;
        let ((tag, oid), _) = tlv(alg)?;
        (tag == 0x06).then(|| oid.to_vec())
    })();
    // sha384WithRSAEncryption 1.2.840.113549.1.1.12, ecdsa-with-SHA384
    // 1.2.840.10045.4.3.3, sha512WithRSAEncryption …1.1.13, ecdsa-with-SHA512
    // 1.2.840.10045.4.3.4.
    match oid.as_deref() {
        Some([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C])
        | Some([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03]) => SigHash::Sha384,
        Some([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D])
        | Some([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04]) => SigHash::Sha512,
        _ => SigHash::Sha256,
    }
}

// --- Certificate / key loading (PEM) ---

/// Load one or more certificates from a PEM file.
pub fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let f = File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let mut r = BufReader::new(f);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut r).collect();
    let certs = certs.map_err(|e| format!("parse certs {path}: {e}"))?;
    if certs.is_empty() {
        return Err(format!("no certificates in {path}"));
    }
    Ok(certs)
}

/// Load a private key from a PEM file (PKCS#8, RSA, or SEC1).
pub fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let f = File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let mut r = BufReader::new(f);
    rustls_pemfile::private_key(&mut r)
        .map_err(|e| format!("parse key {path}: {e}"))?
        .ok_or_else(|| format!("no private key in {path}"))
}

fn root_store(ca_path: &str) -> Result<Arc<RootCertStore>, String> {
    let mut roots = RootCertStore::empty();
    for c in load_certs(ca_path)? {
        roots.add(c).map_err(|e| format!("add CA cert: {e}"))?;
    }
    Ok(Arc::new(roots))
}

// --- Server-side config builders ---

/// A one-way-TLS server config from a cert + key (clients are NOT required to
/// present a certificate). For client-facing TLS where clients authenticate
/// with SCRAM/Basic, not certs.
pub fn server_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>, String> {
    install_crypto_provider();
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("server TLS config: {e}"))?;
    Ok(Arc::new(cfg))
}

/// A mutual-TLS server config: clients MUST present a cert signed by `ca_path`.
pub fn server_config_mtls(
    cert_path: &str,
    key_path: &str,
    ca_path: &str,
) -> Result<Arc<ServerConfig>, String> {
    install_crypto_provider();
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let roots = root_store(ca_path)?;
    let verifier = rustls::server::WebPkiClientVerifier::builder(roots)
        .build()
        .map_err(|e| format!("build client-cert verifier: {e}"))?;
    let cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| format!("server mTLS config: {e}"))?;
    Ok(Arc::new(cfg))
}

/// A server config that REQUESTS a client certificate but does not require
/// one: a client presenting a cert chaining to `ca_path` is verified (and
/// the connection carries its cert for identity mapping); a client with no
/// cert still connects and authenticates some other way. A cert that fails
/// verification is refused at the handshake.
pub fn server_config_optional_client_auth(
    cert_path: &str,
    key_path: &str,
    ca_path: &str,
) -> Result<Arc<ServerConfig>, String> {
    install_crypto_provider();
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let roots = root_store(ca_path)?;
    let verifier = rustls::server::WebPkiClientVerifier::builder(roots)
        .allow_unauthenticated()
        .build()
        .map_err(|e| format!("build client-cert verifier: {e}"))?;
    let cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| format!("server TLS config: {e}"))?;
    Ok(Arc::new(cfg))
}

/// Accept an inbound TLS connection on an already-accepted TCP socket.
pub fn accept_tls(tcp: TcpStream, cfg: Arc<ServerConfig>) -> io::Result<Stream> {
    tcp.set_nodelay(true).ok();
    let mut conn = ServerConnection::new(cfg).map_err(tls_io_err)?;
    let mut tcp = tcp;
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp)?;
    }
    Ok(Stream::ServerTls(Box::new(StreamOwned::new(conn, tcp))))
}

// --- Client-side config builders ---

/// How a TLS client verifies the server it connects to.
#[derive(Debug, Clone)]
pub enum ClientVerify {
    /// Trust server certs chaining to this CA file (the cluster CA).
    CaFile(String),
    /// Trust the OS/webpki default roots (for public CAs).
    WebpkiDefaults,
    /// Skip verification entirely — dev/self-signed only. INSECURE.
    Insecure,
}

/// Build a client TLS config with the given verification policy. When
/// `client_cert`/`client_key` are set, the client also presents a certificate
/// (for mutual TLS); otherwise it authenticates by other means (SCRAM/Basic).
pub fn client_config(
    verify: ClientVerify,
    client_cert: Option<(&str, &str)>,
) -> Result<Arc<ClientConfig>, String> {
    install_crypto_provider();
    let builder = match verify {
        ClientVerify::CaFile(ca) => {
            let roots = root_store(&ca)?;
            ClientConfig::builder().with_root_certificates((*roots).clone())
        }
        ClientVerify::WebpkiDefaults => {
            let roots = RootCertStore {
                roots: webpki_roots_or_empty(),
            };
            ClientConfig::builder().with_root_certificates(roots)
        }
        ClientVerify::Insecure => ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(insecure::NoVerify)),
    };
    let cfg = match client_cert {
        Some((cert, key)) => builder
            .with_client_auth_cert(load_certs(cert)?, load_key(key)?)
            .map_err(|e| format!("client cert: {e}"))?,
        None => builder.with_no_client_auth(),
    };
    Ok(Arc::new(cfg))
}

/// Wrap an already-connected TCP socket in a client TLS session and complete
/// the handshake. `server_name` is the SNI/verification name.
pub fn connect_tls(
    tcp: TcpStream,
    cfg: Arc<ClientConfig>,
    server_name: &str,
) -> io::Result<Stream> {
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let mut conn = ClientConnection::new(cfg, name).map_err(tls_io_err)?;
    let mut tcp = tcp;
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp)?;
    }
    Ok(Stream::ClientTls(Box::new(StreamOwned::new(conn, tcp))))
}

/// Peek the first byte of an accepted socket to tell a TLS ClientHello
/// (`0x16`, TLS handshake record) from a plaintext protocol — for a server
/// that serves both on one port (opportunistic TLS). Returns `(is_tls, tcp)`;
/// the peeked byte stays in the socket buffer for the real reader.
pub fn peek_is_tls(tcp: &TcpStream) -> io::Result<bool> {
    let mut b = [0u8; 1];
    let n = tcp.peek(&mut b)?;
    Ok(n == 1 && b[0] == 0x16)
}

fn tls_io_err(e: rustls::Error) -> io::Error {
    io::Error::other(format!("tls: {e}"))
}

fn webpki_roots_or_empty() -> Vec<rustls::pki_types::TrustAnchor<'static>> {
    // Mozilla's bundle, compiled in — public-CA verification behaves
    // identically on every platform. (This returned an EMPTY store until
    // 2026-08-23, so WebpkiDefaults failed closed on every cert; the
    // inference client's verify = "system" only ever worked against
    // servers it could not verify. Fail-closed, so no one was exposed —
    // just unable to connect.)
    webpki_roots::TLS_SERVER_ROOTS.to_vec()
}

mod insecure {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    /// A verifier that accepts ANY server certificate. INSECURE — dev only.
    #[derive(Debug)]
    pub struct NoVerify;

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA256,
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    /// RFC 5929: the binding is the prefixed certificate hash, with the
    /// hash chosen by the certificate's signature algorithm.
    #[test]
    fn tls_server_end_point_follows_the_signature_hash() {
        use rcgen::{CertificateParams, KeyPair};
        let p = CertificateParams::new(vec!["skaidb".to_string()]).unwrap();
        let k256 = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let c256 = p.clone().self_signed(&k256).unwrap();
        let b = super::tls_server_end_point(c256.der());
        assert!(b.starts_with(b"tls-server-end-point:"));
        assert_eq!(b.len(), 21 + 32);
        assert_eq!(
            &b[21..],
            ring::digest::digest(&ring::digest::SHA256, c256.der()).as_ref()
        );
        let k384 = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let c384 = p.self_signed(&k384).unwrap();
        let b = super::tls_server_end_point(c384.der());
        assert_eq!(b.len(), 21 + 48, "SHA-384 for an ECDSA-P384/SHA-384 certificate");
        assert_eq!(super::tls_server_end_point(b"garbage").len(), 21 + 32);
    }

    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    /// Mint a CA + a leaf cert (SAN `localhost`) into `dir`; return CA path.
    fn mint(dir: &std::path::Path) -> (String, String, String) {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        let mut ca_p = CertificateParams::new(Vec::new()).unwrap();
        ca_p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_p.self_signed(&ca_key).unwrap();
        let leaf_p = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = leaf_p.signed_by(&leaf_key, &ca, &ca_key).unwrap();
        let ca_path = dir.join("ca.crt");
        let crt = dir.join("s.crt");
        let key = dir.join("s.key");
        std::fs::write(&ca_path, ca.pem()).unwrap();
        std::fs::write(&crt, leaf.pem()).unwrap();
        std::fs::write(&key, leaf_key.serialize_pem()).unwrap();
        (
            ca_path.to_str().unwrap().into(),
            crt.to_str().unwrap().into(),
            key.to_str().unwrap().into(),
        )
    }

    fn tmp() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("skaidb-net-{:?}", thread::current().id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// One-way client TLS (server cert, no client cert): the driver-to-DB shape.
    /// A CA-trusting client connects, and bytes flow encrypted end to end.
    #[test]
    fn one_way_client_tls_round_trip() {
        let dir = tmp();
        let (ca, crt, key) = mint(&dir);
        let scfg = server_config(&crt, &key).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut s = accept_tls(sock, scfg).unwrap();
            let mut b = [0u8; 4];
            s.read_exact(&mut b).unwrap();
            s.write_all(&b).unwrap(); // echo
            s.flush().unwrap();
        });
        let ccfg = client_config(ClientVerify::CaFile(ca), None).unwrap();
        let tcp = TcpStream::connect(addr).unwrap();
        let mut s = connect_tls(tcp, ccfg, "localhost").unwrap();
        assert!(s.is_tls());
        s.write_all(b"ping").unwrap();
        s.flush().unwrap();
        let mut echo = [0u8; 4];
        s.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, b"ping");
        srv.join().unwrap();
    }

    /// A client that does NOT trust the server's CA is rejected...
    #[test]
    fn untrusted_ca_client_is_rejected() {
        let good = tmp();
        let (_ca, crt, key) = mint(&good);
        let evil = tmp();
        let (evil_ca, _, _) = mint(&evil); // a different CA
        let scfg = server_config(&crt, &key).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = thread::spawn(move || {
            if let Ok((sock, _)) = listener.accept() {
                let _ = accept_tls(sock, scfg); // handshake may fail; fine
            }
        });
        let ccfg = client_config(ClientVerify::CaFile(evil_ca), None).unwrap();
        let tcp = TcpStream::connect(addr).unwrap();
        let mut s = connect_tls(tcp, ccfg, "localhost").unwrap();
        // Handshake completes lazily; the verification failure surfaces on IO.
        let failed = s.write_all(b"ping").and_then(|_| s.flush()).is_err()
            || {
                let mut b = [0u8; 1];
                s.read_exact(&mut b).is_err()
            };
        assert!(failed, "untrusted-CA client must not exchange data");
        let _ = srv.join();
    }

    /// ...but Insecure mode accepts a self-signed server (dev escape hatch).
    #[test]
    fn insecure_mode_accepts_self_signed() {
        let dir = tmp();
        let (_ca, crt, key) = mint(&dir);
        let scfg = server_config(&crt, &key).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut s = accept_tls(sock, scfg).unwrap();
            let mut b = [0u8; 4];
            s.read_exact(&mut b).unwrap();
            s.write_all(&b).unwrap();
            s.flush().unwrap();
        });
        let ccfg = client_config(ClientVerify::Insecure, None).unwrap();
        let tcp = TcpStream::connect(addr).unwrap();
        let mut s = connect_tls(tcp, ccfg, "anything").unwrap();
        s.write_all(b"ping").unwrap();
        s.flush().unwrap();
        let mut echo = [0u8; 4];
        s.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, b"ping");
        srv.join().unwrap();
    }

    #[test]
    fn peek_discriminates_tls_hello() {
        // A raw 0x16 first byte reads as TLS; anything else as plaintext.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let h = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            peek_is_tls(&sock).unwrap()
        });
        let mut c = TcpStream::connect(addr).unwrap();
        c.write_all(&[0x16, 0x03, 0x01]).unwrap();
        c.flush().unwrap();
        assert!(h.join().unwrap(), "0x16 first byte is a TLS ClientHello");
    }
}
