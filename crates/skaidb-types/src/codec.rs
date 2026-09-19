//! Lossless binary serialization for [`Value`].
//!
//! Distinct from [`Value::encode_key`], which is an order-preserving (and for
//! decimals lossy) *key* encoding. This codec round-trips every variant exactly
//! and is used to store row documents on disk and ship them on the wire.
//!
//! All integers are little-endian; variable-length parts carry a `u32` length.

use crate::value::{Decimal, Document, Uuid, Value, ValueError};

mod tag {
    pub const NULL: u8 = 0;
    pub const BOOL: u8 = 1;
    pub const INT: u8 = 2;
    pub const FLOAT: u8 = 3;
    pub const DECIMAL: u8 = 4;
    pub const STRING: u8 = 5;
    pub const BYTES: u8 = 6;
    pub const UUID: u8 = 7;
    pub const TIMESTAMP: u8 = 8;
    pub const ARRAY: u8 = 9;
    pub const DOCUMENT: u8 = 10;
}

impl Value {
    /// Serialize losslessly to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_value(&mut out);
        out
    }

    /// Serialize losslessly (the [`Value::encode`] format), appending to `out`
    /// — no intermediate allocation. Distinct from [`Value::encode_into`],
    /// which appends the order-preserving *key* encoding.
    pub fn encode_value_into(&self, out: &mut Vec<u8>) {
        self.encode_value(out);
    }

    /// Encode a borrowed document exactly as `Value::Document(doc).encode()`
    /// would, without cloning the document into a `Value` first.
    pub fn encode_document(doc: &Document) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(tag::DOCUMENT);
        out.extend_from_slice(&(doc.0.len() as u32).to_le_bytes());
        for (k, v) in &doc.0 {
            write_bytes(&mut out, k.as_bytes());
            v.encode_value(&mut out);
        }
        out
    }

    /// Deserialize a value previously produced by [`Value::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Value, ValueError> {
        let mut cur = Cursor { bytes, pos: 0 };
        let v = decode_value(&mut cur)?;
        if cur.pos != bytes.len() {
            return Err(ValueError::UnrepresentableJson(
                "trailing bytes after value",
            ));
        }
        Ok(v)
    }

    /// Deserialize a **top-level document**, materializing only the fields
    /// named in `wanted` (a full document's field names — not paths into
    /// nested documents; nested/array *values* under a wanted top-level key
    /// still decode in full). Fields not in `wanted` are skip-parsed: their
    /// bytes are walked to find the next field's boundary, but never
    /// allocated into a `Value` — this is the whole point. `bytes` must be a
    /// document encoding (as [`Value::encode_document`] produces); anything
    /// else errors, matching [`Value::decode`]'s contract for non-document
    /// top-level values.
    ///
    /// Correctness rests entirely on `wanted` being a superset of every
    /// column the caller will actually read from the result — this function
    /// has no way to know that on its own. A field missing from the
    /// returned `Document` because it was never in `wanted` looks
    /// indistinguishable from a field the source row never had.
    pub fn decode_document_projected(
        bytes: &[u8],
        wanted: &std::collections::HashSet<String>,
    ) -> Result<Document, ValueError> {
        let mut cur = Cursor { bytes, pos: 0 };
        let t = cur.u8()?;
        if t != tag::DOCUMENT {
            return Err(ValueError::UnrepresentableJson(
                "decode_document_projected: not a document",
            ));
        }
        let n = cur.u32()? as usize;
        let mut doc = Document::new();
        // Small `wanted` sets — the common projection — compare field names
        // as RAW BYTES against each wanted key: no UTF-8 validation and no
        // hashing per name (a wide row hashes+validates ~14 names to keep 2
        // otherwise), and a byte-match against a valid-UTF-8 wanted key
        // proves the name's validity for free. The kept key is cloned from
        // `wanted` itself. Larger sets keep the hashed path, where names
        // decode borrowed and a `String` is allocated only for KEPT fields.
        // Reserved fields (name starts with 0x01, e.g. the value-TOAST
        // manifest) are ALWAYS kept regardless of the projection — the
        // engine's resolution step needs them and strips them before any
        // consumer sees the row.
        if wanted.len() <= 8 {
            let keys: Vec<&String> = wanted.iter().collect();
            for _ in 0..n {
                let len = cur.u32()? as usize;
                let raw = cur.take_borrowed(len)?;
                match keys.iter().find(|k| k.as_bytes() == raw) {
                    Some(k) => {
                        doc.insert((*k).clone(), decode_value(&mut cur)?);
                    }
                    None if raw.first() == Some(&1) => {
                        let key = std::str::from_utf8(raw).map_err(|_| {
                            ValueError::UnrepresentableJson("invalid utf-8 in string")
                        })?;
                        doc.insert(key.to_owned(), decode_value(&mut cur)?);
                    }
                    None => skip_value(&mut cur)?,
                }
            }
        } else {
            for _ in 0..n {
                let key = cur.str_ref()?;
                if wanted.contains(key) || key.as_bytes().first() == Some(&1) {
                    doc.insert(key.to_owned(), decode_value(&mut cur)?);
                } else {
                    skip_value(&mut cur)?;
                }
            }
        }
        if cur.pos != bytes.len() {
            return Err(ValueError::UnrepresentableJson(
                "trailing bytes after value",
            ));
        }
        Ok(doc)
    }

    /// One borrowed walk over an encoded top-level document: decode ONLY the
    /// values of the named `wanted` fields (positionally into the returned
    /// Vec; `None` = absent) and report whether any RESERVED field (name
    /// starting 0x01 — e.g. the value-TOAST manifest) is present. Nothing
    /// else allocates: unwanted fields are skip-parsed, names are compared
    /// as raw bytes.
    ///
    /// This is the borrowed-row-view primitive behind filter fast-reject
    /// (read-path RFC step 5, first slice): a scan can test a row's filter
    /// constraints against these values and drop non-matches without ever
    /// building a `Document`. The reserved flag exists because a caller
    /// deciding anything from these values must know when the row's real
    /// values live out-of-line.
    pub fn scan_fields<S: AsRef<str>>(
        bytes: &[u8],
        wanted: &[S],
    ) -> Result<(Vec<Option<Value>>, bool), ValueError> {
        let mut out = Vec::new();
        let reserved = Self::scan_fields_into(bytes, wanted, &mut out)?;
        Ok((out, reserved))
    }

    /// [`Value::scan_fields`] into a caller-owned buffer (cleared, then
    /// filled positionally) — the per-row form: a fold over 100k rows reuses
    /// one buffer instead of allocating one `Vec` per row. Returns the
    /// reserved-field flag.
    pub fn scan_fields_into<S: AsRef<str>>(
        bytes: &[u8],
        wanted: &[S],
        out: &mut Vec<Option<Value>>,
    ) -> Result<bool, ValueError> {
        out.clear();
        out.resize(wanted.len(), None);
        let mut cur = Cursor { bytes, pos: 0 };
        if cur.u8()? != tag::DOCUMENT {
            return Err(ValueError::UnrepresentableJson("scan_fields: not a document"));
        }
        let n = cur.u32()? as usize;
        let mut reserved = false;
        for _ in 0..n {
            let len = cur.u32()? as usize;
            let raw = cur.take_borrowed(len)?;
            if raw.first() == Some(&1) {
                reserved = true;
            }
            match wanted.iter().position(|w| w.as_ref().as_bytes() == raw) {
                Some(i) => out[i] = Some(decode_value(&mut cur)?),
                None => skip_value(&mut cur)?,
            }
        }
        if cur.pos != bytes.len() {
            return Err(ValueError::UnrepresentableJson(
                "trailing bytes after value",
            ));
        }
        Ok(reserved)
    }

    /// One walk over an encoded top-level document serving the streamed
    /// GROUP BY row shape (borrowed row view): append the order-preserving
    /// ARRAY key of the `key_fields` to `key_out` — byte-identical to
    /// [`Value::encode_array_key_into`] over the decoded values (missing
    /// field = NULL component), but TRANSCODED straight from the stored
    /// bytes, so a `String` group value never materializes — and decode the
    /// `val_fields` (aggregate args) positionally into `vals_out` (`None` =
    /// absent). `spans` is caller-owned scratch (field byte-ranges recorded
    /// during the walk; offsets, not borrows, so one buffer serves every
    /// row). With `key_fields` empty, `key_out` is left untouched. Returns
    /// the reserved-field flag — a `true` means out-of-line values and the
    /// caller must fall back to the decode + resolve path.
    #[allow(clippy::too_many_arguments)]
    pub fn scan_group_row<S: AsRef<str>>(
        bytes: &[u8],
        key_fields: &[S],
        val_fields: &[S],
        key_out: &mut Vec<u8>,
        vals_out: &mut Vec<Option<Value>>,
        spans: &mut Vec<Option<(usize, usize)>>,
    ) -> Result<bool, ValueError> {
        vals_out.clear();
        vals_out.resize(val_fields.len(), None);
        spans.clear();
        spans.resize(key_fields.len(), None);
        let mut cur = Cursor { bytes, pos: 0 };
        if cur.u8()? != tag::DOCUMENT {
            return Err(ValueError::UnrepresentableJson("scan_group_row: not a document"));
        }
        let n = cur.u32()? as usize;
        let mut reserved = false;
        for _ in 0..n {
            let len = cur.u32()? as usize;
            let raw = cur.take_borrowed(len)?;
            if raw.first() == Some(&1) {
                reserved = true;
            }
            let val_hit = val_fields.iter().position(|w| w.as_ref().as_bytes() == raw);
            let key_hit = key_fields.iter().any(|w| w.as_ref().as_bytes() == raw);
            if val_hit.is_none() && !key_hit {
                skip_value(&mut cur)?;
                continue;
            }
            let start = cur.pos;
            match val_hit {
                Some(i) => vals_out[i] = Some(decode_value(&mut cur)?),
                None => skip_value(&mut cur)?,
            }
            if key_hit {
                // The same column may appear at several key positions
                // (`GROUP BY s, s` is degenerate but legal).
                for (i, w) in key_fields.iter().enumerate() {
                    if w.as_ref().as_bytes() == raw {
                        spans[i] = Some((start, cur.pos));
                    }
                }
            }
        }
        if cur.pos != bytes.len() {
            return Err(ValueError::UnrepresentableJson(
                "trailing bytes after value",
            ));
        }
        if !key_fields.is_empty() {
            use crate::value::tag as ktag;
            key_out.push(ktag::ARRAY);
            for span in spans.iter() {
                match span {
                    None => key_out.push(ktag::NULL),
                    Some((a, b)) => transcode_key_value(&bytes[*a..*b], key_out)?,
                }
            }
            key_out.push(ktag::END);
        }
        Ok(reserved)
    }

    /// Whether an encoded top-level document carries any RESERVED field
    /// (name starting 0x01 — value-TOAST manifest, CAS history, …), reading
    /// as few bytes as possible: field names are stored in ascending
    /// `BTreeMap` order, so the walk stops at the first name whose leading
    /// byte exceeds 0x01 — in practice the very first name. This is the gate
    /// that lets a scan hand a row's ENCODED bytes to a borrowed consumer:
    /// reserved rows must take the decode + resolution path instead, because
    /// their real values live out-of-line.
    pub fn doc_has_reserved(bytes: &[u8]) -> Result<bool, ValueError> {
        let mut cur = Cursor { bytes, pos: 0 };
        if cur.u8()? != tag::DOCUMENT {
            return Err(ValueError::UnrepresentableJson(
                "doc_has_reserved: not a document",
            ));
        }
        let n = cur.u32()? as usize;
        for _ in 0..n {
            let len = cur.u32()? as usize;
            let raw = cur.take_borrowed(len)?;
            match raw.first() {
                Some(&1) => return Ok(true),
                Some(&b) if b > 1 => return Ok(false),
                // Empty or 0x00-prefixed name still sorts before reserved.
                _ => skip_value(&mut cur)?,
            }
        }
        Ok(false)
    }

    fn encode_value(&self, out: &mut Vec<u8>) {
        match self {
            Value::Null => out.push(tag::NULL),
            Value::Bool(b) => {
                out.push(tag::BOOL);
                out.push(u8::from(*b));
            }
            Value::Int(i) => {
                out.push(tag::INT);
                out.extend_from_slice(&i.to_le_bytes());
            }
            Value::Float(f) => {
                out.push(tag::FLOAT);
                out.extend_from_slice(&f.to_bits().to_le_bytes());
            }
            Value::Decimal(d) => {
                out.push(tag::DECIMAL);
                out.extend_from_slice(&d.mantissa.to_le_bytes());
                out.extend_from_slice(&d.scale.to_le_bytes());
            }
            Value::String(s) => {
                out.push(tag::STRING);
                write_bytes(out, s.as_bytes());
            }
            Value::Bytes(b) => {
                out.push(tag::BYTES);
                write_bytes(out, b);
            }
            Value::Uuid(u) => {
                out.push(tag::UUID);
                out.extend_from_slice(&u.0);
            }
            Value::Timestamp(t) => {
                out.push(tag::TIMESTAMP);
                out.extend_from_slice(&t.to_le_bytes());
            }
            Value::Array(items) => {
                out.push(tag::ARRAY);
                out.extend_from_slice(&(items.len() as u32).to_le_bytes());
                for item in items {
                    item.encode_value(out);
                }
            }
            Value::Document(doc) => {
                out.push(tag::DOCUMENT);
                out.extend_from_slice(&(doc.0.len() as u32).to_le_bytes());
                for (k, v) in &doc.0 {
                    write_bytes(out, k.as_bytes());
                    v.encode_value(out);
                }
            }
        }
    }
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], ValueError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(ValueError::UnrepresentableJson("length overflow"))?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(ValueError::UnrepresentableJson("unexpected end of input"))?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, ValueError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, ValueError> {
        let mut b = [0u8; 4];
        b.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(b))
    }

    fn i64(&mut self) -> Result<i64, ValueError> {
        let mut b = [0u8; 8];
        b.copy_from_slice(self.take(8)?);
        Ok(i64::from_le_bytes(b))
    }

    fn bytes(&mut self) -> Result<Vec<u8>, ValueError> {
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    fn string(&mut self) -> Result<String, ValueError> {
        String::from_utf8(self.bytes()?)
            .map_err(|_| ValueError::UnrepresentableJson("invalid utf-8 in string"))
    }
}

impl<'a> Cursor<'a> {
    /// Like [`Cursor::take`], but the returned slice borrows the underlying
    /// buffer (`'a`), not the cursor — callers can hold it across further
    /// cursor advances.
    fn take_borrowed(&mut self, n: usize) -> Result<&'a [u8], ValueError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(ValueError::UnrepresentableJson("length overflow"))?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(ValueError::UnrepresentableJson("unexpected end of input"))?;
        self.pos = end;
        Ok(slice)
    }

    /// A length-prefixed string as a borrowed `&str` — no allocation. The
    /// projected document decode reads every top-level field NAME through
    /// this: a wide row whose fields are mostly skip-parsed used to pay one
    /// `String` allocation per name per row anyway, which was a top-five CPU
    /// cost of a range `GROUP BY` over a wide table (perf-traced on prod,
    /// 2026-07-27).
    fn str_ref(&mut self) -> Result<&'a str, ValueError> {
        let len = self.u32()? as usize;
        std::str::from_utf8(self.take_borrowed(len)?)
            .map_err(|_| ValueError::UnrepresentableJson("invalid utf-8 in string"))
    }
}

/// Append the order-preserving KEY encoding of one stored VALUE encoding —
/// byte-identical to `decode_value(bytes)?.encode_into(out)` for every value,
/// without materializing the `Value` (scalars transcode in place; nested
/// arrays/documents, rare as group keys, fall back to decode-then-encode).
/// Byte-parity with the decode path is pinned by
/// `scan_group_row_key_matches_decoded_encode`.
fn transcode_key_value(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), ValueError> {
    use crate::value::tag as ktag;
    let mut cur = Cursor { bytes, pos: 0 };
    let t = cur.u8()?;
    match t {
        tag::NULL => out.push(ktag::NULL),
        tag::BOOL => {
            out.push(ktag::BOOL);
            // Normalize exactly like decode (`!= 0`) so parity holds even
            // for a nonstandard stored byte.
            out.push(u8::from(cur.u8()? != 0));
        }
        tag::INT => {
            out.push(ktag::INT);
            crate::value::encode_i64(cur.i64()?, out);
        }
        tag::FLOAT => {
            out.push(ktag::FLOAT);
            crate::value::encode_f64(f64::from_bits(cur.i64()? as u64), out);
        }
        tag::DECIMAL => {
            let mut m = [0u8; 16];
            m.copy_from_slice(cur.take(16)?);
            let scale = cur.u32()?;
            out.push(ktag::DECIMAL);
            crate::value::encode_f64(Decimal::new(i128::from_le_bytes(m), scale).to_f64(), out);
        }
        tag::STRING => {
            let len = cur.u32()? as usize;
            let raw = cur.take(len)?;
            // Validate like `Cursor::string` so corrupt data errors here
            // exactly as it would on the decode path.
            if std::str::from_utf8(raw).is_err() {
                return Err(ValueError::UnrepresentableJson("invalid utf-8 in string"));
            }
            out.push(ktag::STRING);
            crate::value::encode_bytes(raw, out);
        }
        tag::BYTES => {
            let len = cur.u32()? as usize;
            let raw = cur.take(len)?;
            out.push(ktag::BYTES);
            crate::value::encode_bytes(raw, out);
        }
        tag::UUID => {
            out.push(ktag::UUID);
            out.extend_from_slice(cur.take(16)?);
        }
        tag::TIMESTAMP => {
            out.push(ktag::TIMESTAMP);
            crate::value::encode_i64(cur.i64()?, out);
        }
        tag::ARRAY | tag::DOCUMENT => {
            let mut cur = Cursor { bytes, pos: 0 };
            decode_value(&mut cur)?.encode_into(out);
        }
        _ => return Err(ValueError::UnrepresentableJson("unknown value tag")),
    }
    Ok(())
}

fn decode_value(cur: &mut Cursor<'_>) -> Result<Value, ValueError> {
    let t = cur.u8()?;
    Ok(match t {
        tag::NULL => Value::Null,
        tag::BOOL => Value::Bool(cur.u8()? != 0),
        tag::INT => Value::Int(cur.i64()?),
        tag::FLOAT => Value::Float(f64::from_bits(cur.i64()? as u64)),
        tag::DECIMAL => {
            let mut m = [0u8; 16];
            m.copy_from_slice(cur.take(16)?);
            let scale = cur.u32()?;
            Value::Decimal(Decimal::new(i128::from_le_bytes(m), scale))
        }
        tag::STRING => Value::String(cur.string()?),
        tag::BYTES => Value::Bytes(cur.bytes()?),
        tag::UUID => {
            let mut u = [0u8; 16];
            u.copy_from_slice(cur.take(16)?);
            Value::Uuid(Uuid(u))
        }
        tag::TIMESTAMP => Value::Timestamp(cur.i64()?),
        tag::ARRAY => {
            let n = cur.u32()? as usize;
            let mut items = Vec::with_capacity(n);
            for _ in 0..n {
                items.push(decode_value(cur)?);
            }
            Value::Array(items)
        }
        tag::DOCUMENT => {
            let n = cur.u32()? as usize;
            let mut doc = Document::new();
            for _ in 0..n {
                let key = cur.string()?;
                let val = decode_value(cur)?;
                doc.insert(key, val);
            }
            Value::Document(doc)
        }
        _ => return Err(ValueError::UnrepresentableJson("unknown value tag")),
    })
}

/// Advance `cur` past one encoded value without allocating it — the same
/// shape as [`decode_value`], but a fixed-size `take`/skip in place of each
/// `Vec`/`String`/`Document` construction. Used by
/// [`Value::decode_document_projected`] to walk past fields the caller
/// doesn't want without paying their decode cost (the entire point: a large
/// unwanted `String`/`Bytes` field skips in O(1) beyond reading its length).
fn skip_value(cur: &mut Cursor<'_>) -> Result<(), ValueError> {
    let t = cur.u8()?;
    match t {
        tag::NULL => {}
        tag::BOOL => {
            cur.u8()?;
        }
        tag::INT | tag::FLOAT | tag::TIMESTAMP => {
            cur.i64()?;
        }
        tag::DECIMAL => {
            cur.take(16)?;
            cur.u32()?;
        }
        tag::STRING | tag::BYTES => {
            let len = cur.u32()? as usize;
            cur.take(len)?;
        }
        tag::UUID => {
            cur.take(16)?;
        }
        tag::ARRAY => {
            let n = cur.u32()? as usize;
            for _ in 0..n {
                skip_value(cur)?;
            }
        }
        tag::DOCUMENT => {
            let n = cur.u32()? as usize;
            for _ in 0..n {
                let len = cur.u32()? as usize; // key length prefix, no UTF-8
                cur.take(len)?; // check/decode needed — the key is discarded
                skip_value(cur)?;
            }
        }
        _ => return Err(ValueError::UnrepresentableJson("unknown value tag")),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(v: Value) {
        let bytes = v.encode();
        assert_eq!(Value::decode(&bytes).unwrap(), v);
    }

    #[test]
    fn roundtrips_all_variants() {
        roundtrip(Value::Null);
        roundtrip(Value::Bool(true));
        roundtrip(Value::Int(-42));
        roundtrip(Value::Float(3.5));
        roundtrip(Value::Decimal(Decimal::new(12345, 2)));
        roundtrip(Value::String("héllo".into()));
        roundtrip(Value::Bytes(vec![0, 1, 2, 255]));
        roundtrip(Value::Uuid(
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        ));
        roundtrip(Value::Timestamp(1_700_000_000_000));
        roundtrip(Value::Array(vec![
            Value::Int(1),
            Value::Null,
            Value::Bool(false),
        ]));
    }

    #[test]
    fn roundtrips_nested_document() {
        let mut inner = Document::new();
        inner.insert("x", Value::Int(1));
        inner.insert("y", Value::Array(vec![Value::String("a".into())]));
        let mut doc = Document::new();
        doc.insert("id", Value::Int(7));
        doc.insert("nested", Value::Document(inner));
        roundtrip(Value::Document(doc));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = Value::Int(1).encode();
        bytes.push(0xFF);
        assert!(Value::decode(&bytes).is_err());
    }

    #[test]
    fn decode_rejects_truncated() {
        let bytes = Value::Int(1).encode();
        assert!(Value::decode(&bytes[..bytes.len() - 1]).is_err());
    }

    fn wide_doc() -> Document {
        let mut doc = Document::new();
        doc.insert("id", Value::Int(7));
        doc.insert("account", Value::String("alice".into()));
        doc.insert("body", Value::String("x".repeat(10_000))); // the field we want to skip
        doc.insert("tags", Value::Array(vec![Value::String("a".into()), Value::Int(2)]));
        doc.insert(
            "meta",
            Value::Document({
                let mut m = Document::new();
                m.insert("nested_big", Value::String("y".repeat(5_000)));
                m.insert("nested_small", Value::Int(1));
                m
            }),
        );
        doc.insert("flag", Value::Bool(true));
        doc.insert("amount", Value::Decimal(Decimal::new(12345, 2)));
        doc.insert("when", Value::Timestamp(1_700_000_000_000));
        doc.insert("nothing", Value::Null);
        doc
    }

    #[test]
    fn projected_decode_returns_only_wanted_fields() {
        let doc = wide_doc();
        let bytes = Value::encode_document(&doc);
        let wanted: std::collections::HashSet<String> =
            ["id".to_string(), "account".to_string()].into_iter().collect();
        let got = Value::decode_document_projected(&bytes, &wanted).unwrap();
        assert_eq!(got.get("id"), Some(&Value::Int(7)));
        assert_eq!(got.get("account"), Some(&Value::String("alice".into())));
        // Every skipped field is simply absent — not null, not present-but-empty.
        assert_eq!(got.get("body"), None);
        assert_eq!(got.get("tags"), None);
        assert_eq!(got.get("meta"), None);
        assert_eq!(got.get("flag"), None);
        assert_eq!(got.0.len(), 2);
    }

    #[test]
    fn projected_decode_wanted_set_covers_every_value_type() {
        // Wanting every field must reproduce the exact full decode — proves
        // the skip-path's cursor bookkeeping for every tag stays in sync
        // with decode_value's (a single off-by-one here would corrupt every
        // field after the first skipped one, not just the skipped one).
        let doc = wide_doc();
        let bytes = Value::encode_document(&doc);
        let wanted: std::collections::HashSet<String> = doc.0.keys().cloned().collect();
        let got = Value::decode_document_projected(&bytes, &wanted).unwrap();
        assert_eq!(got, doc);
    }

    #[test]
    fn projected_decode_wanting_nothing_returns_empty_document() {
        let doc = wide_doc();
        let bytes = Value::encode_document(&doc);
        let wanted: std::collections::HashSet<String> = std::collections::HashSet::new();
        let got = Value::decode_document_projected(&bytes, &wanted).unwrap();
        assert!(got.0.is_empty());
    }

    #[test]
    fn projected_decode_wanting_a_field_the_doc_lacks_is_fine() {
        let doc = wide_doc();
        let bytes = Value::encode_document(&doc);
        let wanted: std::collections::HashSet<String> =
            ["id".to_string(), "does_not_exist".to_string()].into_iter().collect();
        let got = Value::decode_document_projected(&bytes, &wanted).unwrap();
        assert_eq!(got.get("id"), Some(&Value::Int(7)));
        assert_eq!(got.0.len(), 1);
    }

    #[test]
    fn projected_decode_skips_every_field_around_a_wanted_one() {
        // The wanted field isn't first or last — proves skip correctly
        // resumes the cursor so a middle field decodes correctly regardless
        // of what was skipped before or after it.
        let doc = wide_doc();
        let bytes = Value::encode_document(&doc);
        let wanted: std::collections::HashSet<String> = ["flag".to_string()].into_iter().collect();
        let got = Value::decode_document_projected(&bytes, &wanted).unwrap();
        assert_eq!(got.get("flag"), Some(&Value::Bool(true)));
        assert_eq!(got.0.len(), 1);
    }

    #[test]
    fn projected_decode_rejects_non_document_top_level() {
        let bytes = Value::Int(1).encode();
        let wanted: std::collections::HashSet<String> = std::collections::HashSet::new();
        assert!(Value::decode_document_projected(&bytes, &wanted).is_err());
    }

    #[test]
    fn projected_decode_rejects_truncated_skip_region() {
        // Torn bytes inside a SKIPPED field's payload must still error, not
        // silently succeed with a short skip — a truncated big text field
        // must not be treated as an empty one.
        let doc = wide_doc();
        let bytes = Value::encode_document(&doc);
        let truncated = &bytes[..bytes.len() - 20]; // cuts into the trailing fields
        let wanted: std::collections::HashSet<String> = ["id".to_string()].into_iter().collect();
        assert!(Value::decode_document_projected(truncated, &wanted).is_err());
    }

    #[test]
    fn projected_decode_matches_full_decode_over_every_field_subset() {
        // Exhaustive over every possible wanted-subset (2^9 for this doc's 9
        // fields): whatever the projected path returns must be a byte-exact
        // subset of the fully decoded document, for every combination of
        // which fields get skipped around which — no subset-specific
        // cursor-desync bug is invisible here.
        let doc = wide_doc();
        let bytes = Value::encode_document(&doc);
        let all_keys: Vec<String> = doc.0.keys().cloned().collect();
        for mask in 0..(1u32 << all_keys.len()) {
            let wanted: std::collections::HashSet<String> = all_keys
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, k)| k.clone())
                .collect();
            let got = Value::decode_document_projected(&bytes, &wanted).unwrap();
            for k in &wanted {
                assert_eq!(got.get(k), doc.get(k), "mask {mask:#b} key {k}");
            }
            assert_eq!(got.0.len(), wanted.len(), "mask {mask:#b}");
        }
    }

    #[test]
    fn scan_fields_decodes_only_wanted_and_flags_reserved() {
        let mut d = Document::new();
        d.insert("a", Value::Int(7));
        d.insert("big", Value::String("x".repeat(64)));
        d.insert("z", Value::Bool(true));
        let bytes = Value::encode_document(&d);
        let (vals, reserved) = Value::scan_fields(&bytes, &["z", "a", "missing"]).unwrap();
        assert_eq!(vals, vec![Some(Value::Bool(true)), Some(Value::Int(7)), None]);
        assert!(!reserved);

        // A reserved (0x01-prefixed) field flips the flag even when unwanted.
        let mut d = Document::new();
        d.insert("a", Value::Int(1));
        d.insert("\u{1}toast", Value::Bytes(vec![9]));
        let bytes = Value::encode_document(&d);
        let (vals, reserved) = Value::scan_fields(&bytes, &["a"]).unwrap();
        assert_eq!(vals, vec![Some(Value::Int(1))]);
        assert!(reserved);

        // Non-document bytes error rather than lying.
        assert!(Value::scan_fields(&Value::Int(3).encode(), &["a"]).is_err());
    }

    /// The transcoded group key must be byte-identical to decode-then-encode
    /// for EVERY value type — this is what lets the borrowed fold's bytes
    /// arm and Document arm mix within one query (TOASTed rows) and still
    /// land in the same groups.
    #[test]
    fn scan_group_row_key_matches_decoded_encode() {
        let values = vec![
            Value::Null,
            Value::Bool(true),
            Value::Bool(false),
            Value::Int(-42),
            Value::Int(i64::MAX),
            Value::Float(2.5),
            Value::Float(-0.0),
            Value::Decimal(Decimal::new(12345, 2)),
            Value::String("héllo\u{0}world".into()), // NUL exercises key escaping
            Value::Bytes(vec![0, 255, 0]),
            Value::Uuid(Uuid([7; 16])),
            Value::Timestamp(1_700_000_000_000),
            Value::Array(vec![Value::Int(1), Value::String("x".into())]),
            Value::Document({
                let mut d = Document::new();
                d.insert("k", Value::Int(9));
                d
            }),
        ];
        for v in &values {
            let mut d = Document::new();
            d.insert("pad", Value::String("p".repeat(50)));
            d.insert("g", v.clone());
            d.insert("v", Value::Int(3));
            let bytes = Value::encode_document(&d);

            let (mut key, mut vals, mut spans) = (Vec::new(), Vec::new(), Vec::new());
            let reserved =
                Value::scan_group_row(&bytes, &["g"], &["v", "g"], &mut key, &mut vals, &mut spans)
                    .unwrap();
            assert!(!reserved);
            let mut want_key = Vec::new();
            Value::encode_array_key_into([v], &mut want_key);
            assert_eq!(key, want_key, "key mismatch for {v:?}");
            assert_eq!(vals, vec![Some(Value::Int(3)), Some(v.clone())]);
        }

        // Missing key field = NULL component; missing val field = None.
        let mut d = Document::new();
        d.insert("v", Value::Int(1));
        let bytes = Value::encode_document(&d);
        let (mut key, mut vals, mut spans) = (Vec::new(), Vec::new(), Vec::new());
        Value::scan_group_row(&bytes, &["g", "v"], &["absent"], &mut key, &mut vals, &mut spans)
            .unwrap();
        let mut want_key = Vec::new();
        Value::encode_array_key_into([&Value::Null, &Value::Int(1)], &mut want_key);
        assert_eq!(key, want_key);
        assert_eq!(vals, vec![None]);

        // Empty key_fields leaves key_out untouched; reserved flag surfaces.
        let mut d = Document::new();
        d.insert("\u{1}toast", Value::Bytes(vec![9]));
        d.insert("v", Value::Int(1));
        let bytes = Value::encode_document(&d);
        let (mut key, mut vals, mut spans) = (Vec::new(), Vec::new(), Vec::new());
        let reserved =
            Value::scan_group_row(&bytes, &[] as &[&str], &["v"], &mut key, &mut vals, &mut spans)
                .unwrap();
        assert!(reserved);
        assert!(key.is_empty());
    }

    #[test]
    fn doc_has_reserved_probe() {
        let mut d = Document::new();
        d.insert("a", Value::Int(1));
        d.insert("z", Value::String("x".repeat(64)));
        assert!(!Value::doc_has_reserved(&Value::encode_document(&d)).unwrap());

        d.insert("\u{1}toast", Value::Bytes(vec![9]));
        assert!(Value::doc_has_reserved(&Value::encode_document(&d)).unwrap());

        // Names sorting before the reserved prefix (empty, 0x00-prefixed)
        // must not end the walk early in either direction.
        let mut d = Document::new();
        d.insert("", Value::Int(0));
        d.insert("\u{0}x", Value::Int(0));
        d.insert("a", Value::Int(1));
        assert!(!Value::doc_has_reserved(&Value::encode_document(&d)).unwrap());
        let mut d = Document::new();
        d.insert("", Value::Int(0));
        d.insert("\u{1}m", Value::Bytes(vec![1]));
        assert!(Value::doc_has_reserved(&Value::encode_document(&d)).unwrap());

        assert!(Value::doc_has_reserved(&Value::Int(3).encode()).is_err());
    }
}
