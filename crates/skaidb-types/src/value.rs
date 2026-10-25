//! The skaidb value model (SPEC §2.1).
//!
//! Values are self-describing and dynamically typed: the database is schema-less,
//! so a row is just a [`Document`] (an ordered map of field name to [`Value`]).
//! Date/time is represented as unixtime in **milliseconds** as an `int64`.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

/// A 128-bit UUID stored as raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uuid(pub [u8; 16]);

impl Uuid {
    /// The nil UUID (all zero bytes).
    pub const NIL: Uuid = Uuid([0u8; 16]);

    /// Parse the canonical hyphenated form, e.g. `550e8400-e29b-41d4-a716-446655440000`.
    pub fn parse_str(s: &str) -> Result<Uuid, ValueError> {
        let mut bytes = [0u8; 16];
        let hex: String = s.chars().filter(|c| *c != '-').collect();
        if hex.len() != 32 {
            return Err(ValueError::InvalidUuid(s.to_string()));
        }
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| ValueError::InvalidUuid(s.to_string()))?;
        }
        Ok(Uuid(bytes))
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }
}

/// A fixed-point decimal: `mantissa * 10^-scale`.
///
/// Phase 1 keeps an exact mantissa for arithmetic but orders decimals by their
/// `f64` projection in key encoding (see [`Value::encode_into`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Decimal {
    pub mantissa: i128,
    pub scale: u32,
}

impl Decimal {
    pub fn new(mantissa: i128, scale: u32) -> Self {
        Decimal { mantissa, scale }
    }

    /// Largest scale `Display` renders positionally (`0.000…d`). Past it
    /// the exact value is written in scientific notation,
    /// `<mantissa>E-<scale>` (`1E-70000`): a positional rendering is
    /// `scale` characters long — gigabytes at the scales a `u32` admits —
    /// and the formatter's padding width stops at `u16::MAX` anyway. Every
    /// `u32` scale is stored and shipped unchanged (the codec is a fixed
    /// 16 + 4 bytes); only the text form switches.
    pub const MAX_PLAIN_SCALE: u32 = 1_000;

    /// Lossy projection to `f64`, used for ordering and arithmetic interop.
    pub fn to_f64(self) -> f64 {
        // `powi` takes an `i32`. Anything past ~10^308 is infinite, so a
        // scale beyond a few hundred projects to ±0 whatever its size;
        // clamping keeps that true instead of letting `as i32` wrap a huge
        // scale negative (1E-3000000000 came out as +inf).
        let scale = self.scale.min(2 * Self::MAX_PLAIN_SCALE) as i32;
        self.mantissa as f64 / 10f64.powi(scale)
    }

    /// The same number with no trailing zeros in its mantissa (`1.00` →
    /// `1`, `0.000` → `0`, `-2.50` → `-2.5`): every representation of one
    /// value normalises to one `(mantissa, scale)`, so equal decimals meet
    /// on it and distinct ones never do. `1E-70000` stays as it is (its
    /// mantissa has no trailing zero to drop).
    pub fn normalized(self) -> Decimal {
        let (mut mantissa, mut scale) = (self.mantissa, self.scale);
        if mantissa == 0 {
            return Decimal { mantissa: 0, scale: 0 };
        }
        while scale > 0 && mantissa % 10 == 0 {
            mantissa /= 10;
            scale -= 1;
        }
        Decimal { mantissa, scale }
    }

    /// The exact, canonical bytes of this number: its normalised mantissa
    /// (big-endian `i128`) and scale (big-endian `u32`), 20 bytes. Equal
    /// decimals give equal bytes and distinct ones distinct bytes, which
    /// the `f64` projection [`Value::encode_key`] orders by cannot promise
    /// (`1.000000001` and `1.0000000010000000001` project to one float).
    pub fn exact_bytes(self) -> [u8; 20] {
        let n = self.normalized();
        let mut out = [0u8; 20];
        out[..16].copy_from_slice(&n.mantissa.to_be_bytes());
        out[16..].copy_from_slice(&n.scale.to_be_bytes());
        out
    }
}

impl fmt::Display for Decimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.scale == 0 {
            return write!(f, "{}", self.mantissa);
        }
        let sign = if self.mantissa < 0 { "-" } else { "" };
        let digits = self.mantissa.unsigned_abs().to_string();
        if self.scale > Self::MAX_PLAIN_SCALE {
            return write!(f, "{sign}{digits}E-{}", self.scale);
        }
        let scale = self.scale as usize;
        if digits.len() <= scale {
            // `0.` then the zeros up to the first significant digit, written
            // piecewise: `{:0>width$}` panics past a width of `u16::MAX`
            // ("Formatting argument out of range"), which is how a bound
            // `Decimal('1E-70000')` used to drop the connection.
            write!(f, "{sign}0.")?;
            for _ in digits.len()..scale {
                f.write_str("0")?;
            }
            f.write_str(&digits)
        } else {
            let split = digits.len() - scale;
            write!(f, "{sign}{}.{}", &digits[..split], &digits[split..])
        }
    }
}

/// An ordered map of field name to [`Value`]; the unit of a stored row.
///
/// Keys are kept sorted so that encodings are canonical and deterministic.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Document(pub BTreeMap<String, Value>);

impl Document {
    pub fn new() -> Self {
        Document(BTreeMap::new())
    }

    pub fn insert(&mut self, key: impl Into<String>, value: Value) -> &mut Self {
        self.0.insert(key.into(), value);
        self
    }

    /// Look up a field; a missing field is the caller's cue to treat it as `NULL`.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }

    /// Resolve a dotted field path like `a.b.c`, descending nested documents.
    pub fn get_path(&self, path: &str) -> Option<&Value> {
        // Top-level fields (no dot) are the common case in predicates and
        // projections; skip the segment machinery for them.
        match path.split_once('.') {
            None => self.get(path),
            Some((first, rest)) => {
                let mut doc = match self.get(first)? {
                    Value::Document(d) => d,
                    _ => return None,
                };
                let mut rest = rest;
                while let Some((part, tail)) = rest.split_once('.') {
                    match doc.get(part)? {
                        Value::Document(d) => doc = d,
                        _ => return None,
                    }
                    rest = tail;
                }
                doc.get(rest)
            }
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The dynamic type tag of a [`Value`]. Ordering matches the key-encoding order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueType {
    Null,
    Bool,
    Int,
    Float,
    Decimal,
    String,
    Bytes,
    Uuid,
    Timestamp,
    Array,
    Document,
}

/// A dynamically typed skaidb value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Decimal(Decimal),
    String(String),
    Bytes(Vec<u8>),
    Uuid(Uuid),
    /// Unixtime in milliseconds.
    Timestamp(i64),
    Array(Vec<Value>),
    Document(Document),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => write!(f, "NULL"),
            Value::Bool(b) => write!(f, "{b}"),
            Value::Int(i) => write!(f, "{i}"),
            Value::Float(x) => write!(f, "{x}"),
            Value::Decimal(d) => write!(f, "{d}"),
            Value::String(s) => write!(f, "{s}"),
            Value::Bytes(b) => {
                write!(f, "0x")?;
                for byte in b {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
            Value::Uuid(u) => write!(f, "{u}"),
            Value::Timestamp(t) => write!(f, "{t}"),
            // Composite values render as their JSON form for readability.
            Value::Array(_) | Value::Document(_) => write!(f, "{}", self.to_json()),
        }
    }
}

/// Type-tag byte prefixes for order-preserving key encoding. Distinct constants
/// keep the encoding stable even if [`ValueType`] variants are reordered.
pub(crate) mod tag {
    pub const NULL: u8 = 0x00;
    pub const BOOL: u8 = 0x01;
    pub const INT: u8 = 0x02;
    pub const FLOAT: u8 = 0x03;
    pub const DECIMAL: u8 = 0x04;
    pub const STRING: u8 = 0x05;
    pub const BYTES: u8 = 0x06;
    pub const UUID: u8 = 0x07;
    pub const TIMESTAMP: u8 = 0x08;
    pub const ARRAY: u8 = 0x09;
    pub const DOCUMENT: u8 = 0x0a;
    /// Terminator for variable-length / nested encodings.
    pub const END: u8 = 0x00;
}

impl Value {
    /// The dynamic type of this value.
    pub fn type_of(&self) -> ValueType {
        match self {
            Value::Null => ValueType::Null,
            Value::Bool(_) => ValueType::Bool,
            Value::Int(_) => ValueType::Int,
            Value::Float(_) => ValueType::Float,
            Value::Decimal(_) => ValueType::Decimal,
            Value::String(_) => ValueType::String,
            Value::Bytes(_) => ValueType::Bytes,
            Value::Uuid(_) => ValueType::Uuid,
            Value::Timestamp(_) => ValueType::Timestamp,
            Value::Array(_) => ValueType::Array,
            Value::Document(_) => ValueType::Document,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Encode an order-preserving key for this value.
    ///
    /// Byte order over the result equals the logical order of values, so the
    /// storage engine can store keys as plain byte strings (SPEC §12).
    pub fn encode_key(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    /// Append the order-preserving encoding of this value to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Value::Null => out.push(tag::NULL),
            Value::Bool(b) => {
                out.push(tag::BOOL);
                out.push(u8::from(*b));
            }
            Value::Int(v) => {
                out.push(tag::INT);
                encode_i64(*v, out);
            }
            Value::Timestamp(v) => {
                out.push(tag::TIMESTAMP);
                encode_i64(*v, out);
            }
            Value::Float(v) => {
                out.push(tag::FLOAT);
                encode_f64(*v, out);
            }
            Value::Decimal(d) => {
                out.push(tag::DECIMAL);
                encode_f64(d.to_f64(), out);
            }
            Value::String(s) => {
                out.push(tag::STRING);
                encode_bytes(s.as_bytes(), out);
            }
            Value::Bytes(b) => {
                out.push(tag::BYTES);
                encode_bytes(b, out);
            }
            Value::Uuid(u) => {
                out.push(tag::UUID);
                out.extend_from_slice(&u.0);
            }
            Value::Array(items) => {
                out.push(tag::ARRAY);
                for item in items {
                    item.encode_into(out);
                }
                out.push(tag::END);
            }
            Value::Document(doc) => {
                out.push(tag::DOCUMENT);
                for (k, v) in &doc.0 {
                    encode_bytes(k.as_bytes(), out);
                    v.encode_into(out);
                }
                out.push(tag::END);
            }
        }
    }

    /// An EXACT equality key: [`Value::encode_key`] except that a decimal,
    /// at any depth, encodes its canonical [`Decimal::exact_bytes`] (as an
    /// escaped, terminated byte string after the decimal tag) instead of
    /// its lossy `f64` projection. Two values give one key exactly when
    /// they are equal (`1.0`, `1.00` and `1` as a decimal meet; `1.0` and
    /// `1.000000001` never do), and the code stays prefix-free, so a tuple
    /// of several components decodes one way. Not order-preserving across
    /// decimals and not an index entry format: for keys compared by
    /// equality only (a UNIQUE reservation).
    pub fn encode_exact_key(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_exact_into(&mut out);
        out
    }

    /// Append [`Value::encode_exact_key`] to `out`.
    pub fn encode_exact_into(&self, out: &mut Vec<u8>) {
        match self {
            Value::Decimal(d) => {
                out.push(tag::DECIMAL);
                encode_bytes(&d.exact_bytes(), out);
            }
            Value::Array(items) => {
                out.push(tag::ARRAY);
                for item in items {
                    item.encode_exact_into(out);
                }
                out.push(tag::END);
            }
            Value::Document(doc) => {
                out.push(tag::DOCUMENT);
                for (k, v) in &doc.0 {
                    encode_bytes(k.as_bytes(), out);
                    v.encode_exact_into(out);
                }
                out.push(tag::END);
            }
            scalar => scalar.encode_into(out),
        }
    }

    /// Whether a decimal occurs in this value at any depth (the one case
    /// where [`Value::encode_exact_key`] and [`Value::encode_key`] differ).
    pub fn contains_decimal(&self) -> bool {
        match self {
            Value::Decimal(_) => true,
            Value::Array(items) => items.iter().any(Value::contains_decimal),
            Value::Document(doc) => doc.0.values().any(Value::contains_decimal),
            _ => false,
        }
    }

    /// Append the order-preserving ARRAY key of the given components to
    /// `out` — byte-identical to `Value::Array(items.to_vec()).encode_key()`
    /// without materializing the array or cloning a component. This is the
    /// hot-loop form for composite keys built per row (a streamed GROUP BY
    /// encodes one per input row into a reused scratch buffer).
    pub fn encode_array_key_into<'a, I: IntoIterator<Item = &'a Value>>(
        items: I,
        out: &mut Vec<u8>,
    ) {
        out.push(tag::ARRAY);
        for item in items {
            item.encode_into(out);
        }
        out.push(tag::END);
    }

    /// Total order over values consistent with [`Value::encode_key`].
    ///
    /// Unlike `PartialOrd` on `f64`, this is total (NaN is ordered by bit
    /// pattern), so it is safe to use as a sort key.
    pub fn total_cmp(&self, other: &Value) -> Ordering {
        self.encode_key().cmp(&other.encode_key())
    }
}

/// The type-tag byte a value's order-preserving key encoding starts with —
/// the byte index entries of one type share, and by which a key range
/// groups values (`NULL` lowest, then bool, int, float, decimal, string,
/// bytes, uuid, timestamp, array, document).
pub fn key_tag(v: &Value) -> u8 {
    match v {
        Value::Null => tag::NULL,
        Value::Bool(_) => tag::BOOL,
        Value::Int(_) => tag::INT,
        Value::Float(_) => tag::FLOAT,
        Value::Decimal(_) => tag::DECIMAL,
        Value::String(_) => tag::STRING,
        Value::Bytes(_) => tag::BYTES,
        Value::Uuid(_) => tag::UUID,
        Value::Timestamp(_) => tag::TIMESTAMP,
        Value::Array(_) => tag::ARRAY,
        Value::Document(_) => tag::DOCUMENT,
    }
}

/// Decode the NUMERIC value an order-preserving key component starts with
/// (`component` begins at the component's type tag): the exact `Int` or
/// `Timestamp`, the exact `Float`, or — for a `Decimal`, which is keyed by
/// its `f64` projection — that projection as a `Float`. `None` for any
/// other tag or a truncated component. The inverse of
/// [`Value::encode_into`] for the numeric types, for walks that must order
/// index entries of different numeric types by value.
pub fn decode_numeric_key(component: &[u8]) -> Option<Value> {
    let (&t, rest) = component.split_first()?;
    let raw = u64::from_be_bytes(rest.get(..8)?.try_into().ok()?);
    const SIGN: u64 = 0x8000_0000_0000_0000;
    let float = || {
        // Inverse of `encode_f64`: positives had the sign bit set,
        // negatives were inverted.
        f64::from_bits(if raw & SIGN != 0 { raw ^ SIGN } else { !raw })
    };
    match t {
        tag::INT => Some(Value::Int((raw ^ SIGN) as i64)),
        tag::TIMESTAMP => Some(Value::Timestamp((raw ^ SIGN) as i64)),
        tag::FLOAT | tag::DECIMAL => Some(Value::Float(float())),
        _ => None,
    }
}

/// Exact comparison of a 64-bit integer with a double: the mathematical
/// order of the two numbers, with no rounding of the integer. An `i64`
/// beyond 2^53 has no exact `f64`, so comparing through `i as f64` makes
/// neighbouring integers (snowflake ids, nanosecond timestamps) equal to
/// one double and to each other. `None` when `f` is NaN.
pub fn cmp_i64_f64(i: i64, f: f64) -> Option<Ordering> {
    if f.is_nan() {
        return None;
    }
    // ±2^63 are exact doubles; everything in [-2^63, 2^63) truncates to an
    // `i64` without loss.
    const TWO_63: f64 = 9_223_372_036_854_775_808.0;
    if f >= TWO_63 {
        return Some(Ordering::Less);
    }
    if f < -TWO_63 {
        return Some(Ordering::Greater);
    }
    let whole = f.trunc();
    Some(match i.cmp(&(whole as i64)) {
        // Same integer part: the fraction (which carries `f`'s sign) decides.
        Ordering::Equal => 0.0f64.partial_cmp(&(f - whole)).unwrap_or(Ordering::Equal),
        other => other,
    })
}

/// Whether `i` is exactly representable as an `f64` (so `i as f64` loses
/// nothing and some double can equal it).
pub fn i64_is_exact_f64(i: i64) -> bool {
    (i as f64) as i128 == i128::from(i)
}

/// The byte slice of `key` covering the array tag plus the first `n`
/// components, where `key` is a [`Value::Array`] encoding produced by
/// [`Value::encode_key`] — the placement prefix for tables distributed by a
/// primary-key prefix.
///
/// Deterministic in the key bytes alone: equal component prefixes yield equal
/// slices, different prefixes yield different slices (each scalar encoding is
/// injective and prefix-free). Returns `None` — callers fall back to the whole
/// key — when `n` is 0, the key is not an array encoding, fewer than `n`
/// components are present, a component within the prefix is itself an
/// array/document (a nested `0x00` byte is ambiguous between a null element
/// and the terminator, so there is no reliable skip), or a `0x00` appears at
/// a component position (NULL and the END terminator share the byte; primary
/// keys never contain NULL, so this only fires on foreign or short keys).
pub fn encoded_array_prefix(key: &[u8], n: usize) -> Option<&[u8]> {
    if n == 0 || key.first() != Some(&tag::ARRAY) {
        return None;
    }
    let mut pos = 1usize;
    for _ in 0..n {
        let t = *key.get(pos)?;
        pos += 1;
        let skip = match t {
            tag::BOOL => 1,
            tag::INT | tag::TIMESTAMP | tag::FLOAT | tag::DECIMAL => 8,
            tag::UUID => 16,
            tag::STRING | tag::BYTES => skip_escaped_bytes(&key[pos.min(key.len())..])?,
            _ => return None,
        };
        pos = pos.checked_add(skip)?;
        if pos > key.len() {
            return None;
        }
    }
    Some(&key[..pos])
}

/// Length of one `encode_bytes` encoding (escaped body + `0x00 0x00`
/// terminator) at the start of `b`; `None` if malformed or truncated.
fn skip_escaped_bytes(b: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    while i < b.len() {
        if b[i] != 0x00 {
            i += 1;
            continue;
        }
        match b.get(i + 1)? {
            0xFF => i += 2,          // escaped 0x00 in the body
            0x00 => return Some(i + 2), // terminator
            _ => return None,
        }
    }
    None
}

pub(crate) fn encode_i64(v: i64, out: &mut Vec<u8>) {
    // Flip the sign bit so two's-complement order becomes unsigned byte order.
    let u = (v as u64) ^ 0x8000_0000_0000_0000;
    out.extend_from_slice(&u.to_be_bytes());
}

pub(crate) fn encode_f64(v: f64, out: &mut Vec<u8>) {
    let bits = v.to_bits();
    // Order-preserving transform: positives flip the sign bit, negatives invert.
    let ord = if bits & 0x8000_0000_0000_0000 == 0 {
        bits | 0x8000_0000_0000_0000
    } else {
        !bits
    };
    out.extend_from_slice(&ord.to_be_bytes());
}

/// Encode a byte string with `0x00` escaped as `0x00 0xFF`, terminated by
/// `0x00 0x00`, so encodings remain prefix-free and order-preserving.
pub(crate) fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    for &b in bytes {
        if b == 0x00 {
            out.push(0x00);
            out.push(0xFF);
        } else {
            out.push(b);
        }
    }
    out.push(0x00);
    out.push(0x00);
}

/// Errors produced when constructing or converting values.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValueError {
    #[error("invalid UUID: {0}")]
    InvalidUuid(String),
    #[error("value out of range for {0}")]
    OutOfRange(&'static str),
    #[error("cannot represent value as JSON: {0}")]
    UnrepresentableJson(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp(a: Value, b: Value) -> Ordering {
        a.total_cmp(&b)
    }

    #[test]
    fn numeric_key_components_decode_back() {
        for v in [
            Value::Int(0),
            Value::Int(-1),
            Value::Int(i64::MIN),
            Value::Int(i64::MAX),
            Value::Timestamp(1_700_000_000_000),
            Value::Float(0.5),
            Value::Float(-0.0),
            Value::Float(-1.5e300),
            Value::Float(f64::INFINITY),
        ] {
            let key = v.encode_key();
            assert_eq!(key[0], key_tag(&v));
            assert_eq!(decode_numeric_key(&key), Some(v.clone()), "{v:?}");
        }
        // A decimal is keyed by its f64 projection.
        let d = Value::Decimal(Decimal::new(125, 2));
        assert_eq!(decode_numeric_key(&d.encode_key()), Some(Value::Float(1.25)));
        assert_eq!(decode_numeric_key(&Value::String("x".into()).encode_key()), None);
        assert_eq!(decode_numeric_key(&[tag::INT, 1, 2]), None);
        // Tags ascend in the documented order.
        let order = [
            Value::Null,
            Value::Bool(false),
            Value::Int(0),
            Value::Float(0.0),
            Value::Decimal(Decimal::new(0, 0)),
            Value::String(String::new()),
            Value::Bytes(Vec::new()),
            Value::Uuid(Uuid::NIL),
            Value::Timestamp(0),
            Value::Array(Vec::new()),
            Value::Document(Document::new()),
        ];
        assert!(order.windows(2).all(|w| key_tag(&w[0]) < key_tag(&w[1])));
    }

    #[test]
    fn int_float_comparison_is_exact_beyond_2_pow_53() {
        use Ordering::*;
        let two53 = 9_007_199_254_740_992i64;
        // 2^53 + 1 rounds to 2^53 as a double; the integers still differ.
        assert_eq!(cmp_i64_f64(two53 + 1, two53 as f64), Some(Greater));
        assert_eq!(cmp_i64_f64(two53, two53 as f64), Some(Equal));
        assert_eq!(cmp_i64_f64(-two53 - 1, -(two53 as f64)), Some(Less));
        // Fractions on either side of zero.
        assert_eq!(cmp_i64_f64(1, 1.5), Some(Less));
        assert_eq!(cmp_i64_f64(2, 1.5), Some(Greater));
        assert_eq!(cmp_i64_f64(-1, -1.5), Some(Greater));
        assert_eq!(cmp_i64_f64(-2, -1.5), Some(Less));
        assert_eq!(cmp_i64_f64(0, -0.0), Some(Equal));
        assert_eq!(cmp_i64_f64(0, 0.25), Some(Less));
        assert_eq!(cmp_i64_f64(0, -0.25), Some(Greater));
        // The ends of the range, infinities and NaN.
        assert_eq!(cmp_i64_f64(i64::MAX, 9_223_372_036_854_775_808.0), Some(Less));
        assert_eq!(cmp_i64_f64(i64::MAX, 9_223_372_036_854_774_784.0), Some(Greater));
        assert_eq!(cmp_i64_f64(i64::MIN, -9_223_372_036_854_775_808.0), Some(Equal));
        assert_eq!(cmp_i64_f64(i64::MIN, f64::NEG_INFINITY), Some(Greater));
        assert_eq!(cmp_i64_f64(i64::MAX, f64::INFINITY), Some(Less));
        assert_eq!(cmp_i64_f64(7, f64::NAN), None);
        assert!(i64_is_exact_f64(two53));
        assert!(!i64_is_exact_f64(two53 + 1));
        assert!(!i64_is_exact_f64(i64::MAX));
        assert!(i64_is_exact_f64(i64::MIN));
    }

    #[test]
    fn int_order_preserved() {
        assert_eq!(cmp(Value::Int(-5), Value::Int(3)), Ordering::Less);
        assert_eq!(
            cmp(Value::Int(i64::MIN), Value::Int(i64::MAX)),
            Ordering::Less
        );
        assert_eq!(cmp(Value::Int(7), Value::Int(7)), Ordering::Equal);
    }

    #[test]
    fn float_order_preserved() {
        assert_eq!(cmp(Value::Float(-1.0), Value::Float(1.0)), Ordering::Less);
        assert_eq!(cmp(Value::Float(0.0), Value::Float(0.5)), Ordering::Less);
    }

    #[test]
    fn type_rank_orders_across_types() {
        // Null sorts before Bool sorts before Int, etc.
        assert_eq!(cmp(Value::Null, Value::Bool(false)), Ordering::Less);
        assert_eq!(cmp(Value::Bool(true), Value::Int(0)), Ordering::Less);
    }

    #[test]
    fn string_order_is_lexicographic_and_prefix_free() {
        assert_eq!(
            cmp(Value::String("ab".into()), Value::String("abc".into())),
            Ordering::Less
        );
        assert_eq!(
            cmp(Value::String("ab".into()), Value::String("b".into())),
            Ordering::Less
        );
    }

    #[test]
    fn array_orders_elementwise() {
        let a = Value::Array(vec![Value::Int(1), Value::Int(2)]);
        let b = Value::Array(vec![Value::Int(1), Value::Int(3)]);
        assert_eq!(a.total_cmp(&b), Ordering::Less);
    }

    #[test]
    fn document_path_lookup() {
        let mut inner = Document::new();
        inner.insert("c", Value::Int(42));
        let mut outer = Document::new();
        outer.insert("a", Value::Document(inner));
        assert_eq!(outer.get_path("a.c"), Some(&Value::Int(42)));
        assert_eq!(outer.get_path("a.x"), None);
        assert_eq!(outer.get_path("missing"), None);
    }

    #[test]
    fn uuid_roundtrip() {
        let s = "550e8400-e29b-41d4-a716-446655440000";
        let u = Uuid::parse_str(s).unwrap();
        assert_eq!(u.to_string(), s);
        assert!(Uuid::parse_str("not-a-uuid").is_err());
    }

    #[test]
    fn decimal_display() {
        assert_eq!(Decimal::new(12345, 2).to_string(), "123.45");
        assert_eq!(Decimal::new(5, 3).to_string(), "0.005");
        assert_eq!(Decimal::new(-5, 3).to_string(), "-0.005");
        assert_eq!(Decimal::new(42, 0).to_string(), "42");
    }

    /// The exact key meets on equal decimals whatever their scale and
    /// separates decimals the f64 projection collapses; other values
    /// encode as `encode_key` does.
    #[test]
    fn exact_key_is_canonical_for_decimals() {
        let dec = |m: i128, s: u32| Value::Array(vec![Value::Decimal(Decimal::new(m, s))]);
        assert_eq!(dec(10, 1).encode_exact_key(), dec(100, 2).encode_exact_key(), "1.0 == 1.00");
        assert_eq!(dec(1, 0).encode_exact_key(), dec(1_000_000, 6).encode_exact_key(), "1 == 1.000000");
        assert_eq!(dec(0, 5).encode_exact_key(), dec(0, 0).encode_exact_key(), "0.00000 == 0");
        assert_ne!(dec(10, 1).encode_exact_key(), dec(1_000_000_001, 9).encode_exact_key(), "1.0 != 1.000000001");
        // Two decimals one f64 apart: the projection collides, the exact key does not.
        let a = Decimal::new(1_000_000_001, 9);
        let b = Decimal::new(10_000_000_010_000_000_001, 19);
        assert_eq!(Value::Decimal(a).encode_key(), Value::Decimal(b).encode_key());
        assert_ne!(Value::Decimal(a).encode_exact_key(), Value::Decimal(b).encode_exact_key());
        // A decimal never meets another type, and non-decimals are unchanged.
        assert_ne!(dec(1, 0).encode_exact_key(), Value::Array(vec![Value::Int(1)]).encode_exact_key());
        let mixed = Value::Array(vec![Value::String("a".into()), Value::Int(7), Value::Null]);
        assert_eq!(mixed.encode_exact_key(), mixed.encode_key());
        assert!(!mixed.contains_decimal());
        assert!(Value::Array(vec![Value::Document(Document::new().insert("d", Value::Decimal(a)).clone())]).contains_decimal());
        assert_eq!(Decimal::new(-250, 2).normalized(), Decimal::new(-25, 1));
    }

    /// A bound `Decimal('1E-70000')` read back as text panicked the
    /// formatter (`{:0>width$}` stops at `u16::MAX`) and dropped the
    /// connection. Rendering is total now: positional up to
    /// `MAX_PLAIN_SCALE`, exact scientific notation beyond, at any `u32`.
    #[test]
    fn decimal_display_is_total_at_any_scale() {
        assert_eq!(Decimal::new(1, 70_000).to_string(), "1E-70000");
        assert_eq!(Decimal::new(-15, u32::MAX).to_string(), "-15E-4294967295");
        assert_eq!(Decimal::new(123, 65_536).to_string(), "123E-65536");
        assert_eq!(Decimal::new(0, 5_000).to_string(), "0E-5000");
        // Positional right up to the bound, zero-padded exactly.
        let s = Decimal::new(7, Decimal::MAX_PLAIN_SCALE).to_string();
        assert_eq!(s.len(), Decimal::MAX_PLAIN_SCALE as usize + 2);
        assert!(s.starts_with("0.000") && s.ends_with("07"), "{s}");
        assert_eq!(Decimal::new(-7, Decimal::MAX_PLAIN_SCALE + 1).to_string(), "-7E-1001");
        // Value's Display and JSON forms ride on the same rendering.
        assert_eq!(Value::Decimal(Decimal::new(1, 70_000)).to_string(), "1E-70000");
        assert_eq!(
            Value::Decimal(Decimal::new(1, 70_000)).to_json(),
            serde_json::json!("1E-70000")
        );
        // The f64 projection clamps instead of wrapping the exponent.
        assert_eq!(Decimal::new(1, 70_000).to_f64(), 0.0);
        assert_eq!(Decimal::new(1, u32::MAX).to_f64(), 0.0);
        assert!(Decimal::new(-1, 3_000_000_000).to_f64().is_sign_negative());
        assert_eq!(Decimal::new(12345, 2).to_f64(), 123.45);
    }

    fn pk_key(vals: Vec<Value>) -> Vec<u8> {
        Value::Array(vals).encode_key()
    }

    #[test]
    fn array_prefix_covers_first_components_exactly() {
        // prefix(key([a, b]), 1) == full bytes of key([a]) minus the END tag.
        let cases = vec![
            Value::String("tenant-1".into()),
            Value::Int(42),
            Value::Timestamp(1_722_000_000_000),
            Value::Float(2.5),
            Value::Bool(true),
            Value::Uuid(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()),
            Value::Bytes(vec![1, 0, 2, 0, 0, 3]), // embedded zeros exercise escaping
        ];
        for first in cases {
            let solo = pk_key(vec![first.clone()]);
            let full = pk_key(vec![first, Value::String("tail".into())]);
            let p = encoded_array_prefix(&full, 1).expect("prefix");
            assert_eq!(p, &solo[..solo.len() - 1], "component: prefix == solo key sans END");
        }
    }

    #[test]
    fn array_prefix_equal_iff_components_equal() {
        let a = pk_key(vec![Value::String("t1".into()), Value::String("x".into())]);
        let b = pk_key(vec![Value::String("t1".into()), Value::String("y".into())]);
        let c = pk_key(vec![Value::String("t2".into()), Value::String("x".into())]);
        assert_eq!(
            encoded_array_prefix(&a, 1).unwrap(),
            encoded_array_prefix(&b, 1).unwrap()
        );
        assert_ne!(
            encoded_array_prefix(&a, 1).unwrap(),
            encoded_array_prefix(&c, 1).unwrap()
        );
    }

    #[test]
    fn array_prefix_multi_component() {
        let full = pk_key(vec![
            Value::String("org".into()),
            Value::Int(7),
            Value::String("row".into()),
        ]);
        let two = encoded_array_prefix(&full, 2).unwrap();
        let sibling = pk_key(vec![
            Value::String("org".into()),
            Value::Int(7),
            Value::String("other".into()),
        ]);
        assert_eq!(two, encoded_array_prefix(&sibling, 2).unwrap());
        // n == all components consumes everything but the END tag.
        let all = encoded_array_prefix(&full, 3).unwrap();
        assert_eq!(all, &full[..full.len() - 1]);
    }

    #[test]
    fn array_prefix_rejects_unskippable_or_short_keys() {
        // n = 0, non-array input, too few components, nested array/document.
        let full = pk_key(vec![Value::Int(1)]);
        assert_eq!(encoded_array_prefix(&full, 0), None);
        assert_eq!(encoded_array_prefix(&full, 2), None);
        assert_eq!(encoded_array_prefix(&Value::Int(1).encode_key(), 1), None);
        let nested = pk_key(vec![Value::Array(vec![Value::Int(1)]), Value::Int(2)]);
        assert_eq!(encoded_array_prefix(&nested, 1), None);
        let doc = pk_key(vec![Value::Document(Document::new())]);
        assert_eq!(encoded_array_prefix(&doc, 1), None);
        // NULL shares its tag byte with END — ambiguous, so refused.
        let with_null = pk_key(vec![Value::Null, Value::Int(1)]);
        assert_eq!(encoded_array_prefix(&with_null, 1), None);
        // Truncated string component.
        let mut trunc = pk_key(vec![Value::String("abc".into())]);
        trunc.truncate(3);
        assert_eq!(encoded_array_prefix(&trunc, 1), None);
    }
}
