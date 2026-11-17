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

    /// Lossy projection to `f64`, used for keys, ordering and arithmetic
    /// interop. Equal decimals project to one `f64` however they are spelled.
    pub fn to_f64(self) -> f64 {
        // A mantissa up to 2^53 and a power of ten up to 10^22 are exact as
        // `f64`, so their division is correctly rounded. Past those each step
        // rounds on its own and the result depends on the spelling, so those
        // project from the one normalised spelling.
        let exact = self.mantissa.unsigned_abs() <= 1 << 53 && self.scale <= 22;
        let d = if exact { self } else { self.normalized() };
        // `powi` takes an `i32`. Anything past ~10^308 is infinite, so a
        // scale beyond a few hundred projects to ±0 whatever its size;
        // clamping keeps that true instead of letting `as i32` wrap a huge
        // scale negative (1E-3000000000 came out as +inf).
        let scale = d.scale.min(2 * Self::MAX_PLAIN_SCALE) as i32;
        d.mantissa as f64 / 10f64.powi(scale)
    }

    /// Every other `f64` this value's key may hold on disk: an earlier build
    /// divided the mantissa of whatever spelling it was given, so `…3.0` could
    /// land a step away from `…3`. Spellings run to scale 18, the usual widest
    /// fixed-point column: past it a key may be missed. Most values with seven
    /// or more significant digits have one, so this is for reads that missed.
    pub fn earlier_key_projections(self) -> Vec<f64> {
        let d = self.normalized();
        let now = d.to_f64().to_bits();
        let mut out: Vec<f64> = Vec::new();
        let (mut mantissa, mut scale) = (d.mantissa, d.scale);
        while mantissa != 0 && scale <= 18 {
            let p = mantissa as f64 / 10f64.powi(scale as i32);
            if p.to_bits() != now && !out.iter().any(|o| o.to_bits() == p.to_bits()) {
                out.push(p);
            }
            let Some(wider) = mantissa.checked_mul(10) else {
                break;
            };
            mantissa = wider;
            scale += 1;
        }
        out
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

    /// The other keys a primary key of `items` may be stored under, for a
    /// decimal an earlier build keyed by another spelling
    /// ([`Decimal::earlier_key_projections`]). Top-level decimals only, at most
    /// [`Value::EARLIER_KEYS_MAX`]; empty unless one of them has such a key.
    pub fn earlier_array_keys(items: &[&Value]) -> Vec<Vec<u8>> {
        let options: Vec<Vec<f64>> = items
            .iter()
            .map(|v| match v {
                Value::Decimal(d) => d.earlier_key_projections(),
                _ => Vec::new(),
            })
            .collect();
        if options.iter().all(Vec::is_empty) {
            return Vec::new();
        }
        // Per item: `0` is the value as it keys now, `n` its `n-1`th earlier f64.
        let mut pick = vec![0usize; items.len()];
        let mut out = Vec::new();
        loop {
            let mut carry = items.len();
            while carry > 0 {
                carry -= 1;
                pick[carry] += 1;
                if pick[carry] <= options[carry].len() {
                    break;
                }
                pick[carry] = 0;
                if carry == 0 {
                    return out;
                }
            }
            let mut key = vec![tag::ARRAY];
            for (i, item) in items.iter().enumerate() {
                match pick[i] {
                    0 => item.encode_into(&mut key),
                    n => {
                        key.push(tag::DECIMAL);
                        encode_f64(options[i][n - 1], &mut key);
                    }
                }
            }
            key.push(tag::END);
            out.push(key);
            if out.len() == Self::EARLIER_KEYS_MAX {
                return out;
            }
        }
    }

    /// Cap on [`Value::earlier_array_keys`].
    pub const EARLIER_KEYS_MAX: usize = 64;

    /// Total order over values consistent with [`Value::encode_key`].
    ///
    /// Unlike `PartialOrd` on `f64`, this is total (NaN is ordered by bit
    /// pattern), so it is safe to use as a sort key.
    /// Whether this value nests arrays / documents more than `max` levels
    /// deep (a scalar is 0 levels, `[1]` is 1). Stops at the first branch
    /// that is too deep; a scalar costs one comparison.
    pub fn nests_deeper_than(&self, max: usize) -> bool {
        match self {
            Value::Array(items) => match max.checked_sub(1) {
                None => true,
                Some(left) => items.iter().any(|v| v.nests_deeper_than(left)),
            },
            Value::Document(doc) => match max.checked_sub(1) {
                None => true,
                Some(left) => doc.0.values().any(|v| v.nests_deeper_than(left)),
            },
            _ => false,
        }
    }

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

/// Decode an order-preserving ARRAY key ([`Value::encode_key`] of a
/// `Value::Array`) whose components are all exact scalars — `Bool`,
/// `Int`, `Timestamp`, `Float`, `String`, `Bytes`, `Uuid` — into those
/// components. `None` for anything else: a `NULL` component (its tag is
/// the array's terminator, so the decode ends there with bytes left over),
/// a `Decimal` (keyed by its lossy `f64` projection), a nested array or
/// document, a string that is not UTF-8, or a truncated or over-long key.
/// An index entry key (`[values…, row key]`) and a row key (`[pk…]`) are
/// such arrays.
pub fn decode_scalar_key_tuple(bytes: &[u8]) -> Option<Vec<Value>> {
    let (&t, mut rest) = bytes.split_first()?;
    if t != tag::ARRAY {
        return None;
    }
    let mut out = Vec::new();
    loop {
        let (&t, after) = rest.split_first()?;
        rest = match t {
            tag::END => return after.is_empty().then_some(out),
            tag::BOOL => {
                let (&b, after) = after.split_first()?;
                out.push(Value::Bool(match b {
                    0 => false,
                    1 => true,
                    _ => return None,
                }));
                after
            }
            tag::INT | tag::TIMESTAMP | tag::FLOAT => {
                out.push(decode_numeric_key(rest)?);
                after.get(8..)?
            }
            tag::STRING | tag::BYTES => {
                let (raw, after) = decode_escaped(after)?;
                out.push(match t {
                    tag::STRING => Value::String(String::from_utf8(raw).ok()?),
                    _ => Value::Bytes(raw),
                });
                after
            }
            tag::UUID => {
                out.push(Value::Uuid(Uuid(after.get(..16)?.try_into().ok()?)));
                after.get(16..)?
            }
            _ => return None,
        };
    }
}

/// Inverse of `encode_bytes`: the unescaped bytes and what follows their
/// terminator; `None` for a malformed escape or a missing terminator.
fn decode_escaped(buf: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let mut out = Vec::new();
    let mut i = 0usize;
    loop {
        match *buf.get(i)? {
            0x00 => match *buf.get(i + 1)? {
                0x00 => return Some((out, &buf[i + 2..])),
                0xFF => {
                    out.push(0x00);
                    i += 2;
                }
                _ => return None,
            },
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
}

/// Exact comparison of a 64-bit integer with a decimal: the mathematical
/// order of the two numbers. Through the decimal's `f64` projection an
/// integer beyond 2^53 equalled its neighbours (`9007199254740993 =
/// 9007199254740992` held), and so could a key's `=`-twin.
pub fn cmp_i64_decimal(i: i64, d: Decimal) -> Ordering {
    // d = whole + frac / 10^scale, both truncated toward zero (so `frac`
    // carries d's sign). A scale past i128's 38 digits leaves no whole part:
    // every mantissa is smaller than 10^39.
    let (whole, frac) = match 10i128.checked_pow(d.scale) {
        Some(pow) => (d.mantissa / pow, d.mantissa % pow),
        None => (0, d.mantissa),
    };
    match i128::from(i).cmp(&whole) {
        Ordering::Equal => 0.cmp(&frac),
        other => other,
    }
}

/// Exact comparison of two decimals: the scales aligned on the mantissa of
/// the one with fewer digits. A non-zero mantissa scaled past i128 exceeds
/// every other mantissa in magnitude, so its sign decides.
pub fn cmp_decimal(a: Decimal, b: Decimal) -> Ordering {
    if a.scale == b.scale {
        return a.mantissa.cmp(&b.mantissa);
    }
    // Scale the mantissa with the smaller scale up to the larger one.
    let (small, large, flip) = if a.scale < b.scale {
        (a, b, false)
    } else {
        (b, a, true)
    };
    let scaled = 10i128
        .checked_pow(large.scale - small.scale)
        .and_then(|pow| small.mantissa.checked_mul(pow));
    let ord = match scaled {
        Some(m) => m.cmp(&large.mantissa),
        // `10^Δ` itself overflowed (Δ ≥ 39): a zero is still zero.
        None if small.mantissa == 0 => 0i128.cmp(&large.mantissa),
        None => small.mantissa.cmp(&0),
    };
    if flip {
        ord.reverse()
    } else {
        ord
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

/// Exact comparison of a decimal with a double: the mathematical order of
/// the two numbers, neither rounded to the other's precision. `None` when
/// `f` is NaN. (The `=` of a filter compares the pair through the decimal's
/// nearest double instead, as PostgreSQL does; that relation is not
/// transitive — two distinct decimals can both equal one double — so a
/// sort cannot use it.)
pub fn cmp_decimal_f64(d: Decimal, f: f64) -> Option<Ordering> {
    if f.is_nan() {
        return None;
    }
    // Every decimal's magnitude is below 2^127 (an `i128` mantissa, a
    // scale that only shrinks it); -2^127 itself is a mantissa.
    const TWO_127: f64 = 170_141_183_460_469_231_731_687_303_715_884_105_728.0;
    if f >= TWO_127 {
        return Some(Ordering::Less);
    }
    if f < -TWO_127 {
        return Some(Ordering::Greater);
    }
    // Whole parts, both truncated toward zero; a double's is exact, and
    // within `i128` here.
    let whole_f = f.trunc();
    let (whole_d, frac_d) = match 10i128.checked_pow(d.scale) {
        Some(pow) => (d.mantissa / pow, d.mantissa % pow),
        None => (0, d.mantissa),
    };
    match whole_d.cmp(&(whole_f as i128)) {
        Ordering::Equal => {}
        other => return Some(other),
    }
    // Same whole part: the fractions decide, each carrying its number's
    // sign. `f - whole_f` is exact.
    let frac_f = f - whole_f;
    let sign_f = if frac_f > 0.0 {
        1
    } else if frac_f < 0.0 {
        -1
    } else {
        0
    };
    let sign_d = frac_d.signum() as i32;
    if sign_d != sign_f || sign_d == 0 {
        return Some(sign_d.cmp(&sign_f));
    }
    // |frac_d| = r / 10^scale against |frac_f| = m / 2^k, both positive:
    // r * 2^k against m * 10^scale, in integers wide enough to hold them.
    let bits = frac_f.abs().to_bits();
    let exp = ((bits >> 52) & 0x7ff) as u32;
    let low = bits & ((1u64 << 52) - 1);
    let (m, k) = if exp == 0 {
        (low, 1074u32)
    } else {
        (low | (1u64 << 52), 1075 - exp)
    };
    // A fraction of a double is at least 2^-1074; past this scale the
    // decimal's (below 2^127 / 10^scale) is smaller than any.
    const SCALE_BELOW_EVERY_DOUBLE: u32 = 400;
    let magnitude = if d.scale > SCALE_BELOW_EVERY_DOUBLE {
        Ordering::Less
    } else {
        let mut left = wide::from_u128(frac_d.unsigned_abs());
        wide::shl(&mut left, k);
        let mut right = wide::from_u128(u128::from(m));
        wide::mul_pow10(&mut right, d.scale);
        wide::cmp(&left, &right)
    };
    Some(if sign_d < 0 {
        magnitude.reverse()
    } else {
        magnitude
    })
}

/// Unsigned integers of any width, little-endian `u32` limbs with no
/// leading zero limb — only what [`cmp_decimal_f64`] needs.
mod wide {
    use std::cmp::Ordering;

    pub fn from_u128(mut x: u128) -> Vec<u32> {
        let mut out = Vec::new();
        while x != 0 {
            out.push(x as u32);
            x >>= 32;
        }
        out
    }

    pub fn shl(v: &mut Vec<u32>, bits: u32) {
        if v.is_empty() {
            return;
        }
        let (limbs, rest) = ((bits / 32) as usize, bits % 32);
        if rest != 0 {
            let mut carry = 0u32;
            for limb in v.iter_mut() {
                let wide = (u64::from(*limb) << rest) | u64::from(carry);
                *limb = wide as u32;
                carry = (wide >> 32) as u32;
            }
            if carry != 0 {
                v.push(carry);
            }
        }
        v.splice(0..0, std::iter::repeat_n(0, limbs));
    }

    fn mul_small(v: &mut Vec<u32>, by: u32) {
        let mut carry = 0u64;
        for limb in v.iter_mut() {
            let wide = u64::from(*limb) * u64::from(by) + carry;
            *limb = wide as u32;
            carry = wide >> 32;
        }
        if carry != 0 {
            v.push(carry as u32);
        }
    }

    pub fn mul_pow10(v: &mut Vec<u32>, mut pow: u32) {
        while pow >= 9 {
            mul_small(v, 1_000_000_000);
            pow -= 9;
        }
        if pow > 0 {
            mul_small(v, 10u32.pow(pow));
        }
    }

    pub fn cmp(a: &[u32], b: &[u32]) -> Ordering {
        a.len()
            .cmp(&b.len())
            .then_with(|| a.iter().rev().cmp(b.iter().rev()))
    }
}

/// The order an `ORDER BY` ranks two non-NULL values in — a total order,
/// which [`Value::total_cmp`] (the key encoding's: type tag, then value) is
/// too, but this one is by VALUE where the types are comparable: numbers of
/// every type (int, float, decimal, timestamp) rank by their exact
/// mathematical value, a NaN after every number; values of other types
/// follow by type — bools before numbers, then strings, bytes, uuids,
/// arrays, documents — each in its own order.
///
/// It is deliberately not a filter's comparison: that one also reads an
/// ISO-8601 string as the timestamp it names and compares a decimal with a
/// double through the double's precision, and neither relation is
/// transitive (a timestamp below a date string below `'abc'` below — by
/// type — the timestamp again). A sort over a comparison like that has no
/// defined result, and the standard library's aborts when it notices.
pub fn order_cmp(a: &Value, b: &Value) -> Ordering {
    fn rank(v: &Value) -> u8 {
        match v {
            Value::Null => 0,
            Value::Bool(_) => 1,
            Value::Int(_) | Value::Float(_) | Value::Decimal(_) | Value::Timestamp(_) => 2,
            Value::String(_) => 3,
            Value::Bytes(_) => 4,
            Value::Uuid(_) => 5,
            Value::Array(_) => 6,
            Value::Document(_) => 7,
        }
    }
    match rank(a).cmp(&rank(b)) {
        Ordering::Equal => {}
        other => return other,
    }
    // A NaN ranks after every number, and with another NaN.
    let nan = |v: &Value| matches!(v, Value::Float(f) if f.is_nan());
    match (nan(a), nan(b)) {
        (true, true) => return Ordering::Equal,
        (true, false) => return Ordering::Greater,
        (false, true) => return Ordering::Less,
        (false, false) => {}
    }
    match (a, b) {
        (Value::Int(x) | Value::Timestamp(x), Value::Int(y) | Value::Timestamp(y)) => x.cmp(y),
        (Value::Int(x) | Value::Timestamp(x), Value::Float(f)) => {
            cmp_i64_f64(*x, *f).unwrap_or(Ordering::Equal)
        }
        (Value::Float(f), Value::Int(y) | Value::Timestamp(y)) => {
            cmp_i64_f64(*y, *f).unwrap_or(Ordering::Equal).reverse()
        }
        (Value::Int(x) | Value::Timestamp(x), Value::Decimal(d)) => cmp_i64_decimal(*x, *d),
        (Value::Decimal(d), Value::Int(y) | Value::Timestamp(y)) => cmp_i64_decimal(*y, *d).reverse(),
        (Value::Decimal(x), Value::Decimal(y)) => cmp_decimal(*x, *y),
        (Value::Decimal(d), Value::Float(f)) => cmp_decimal_f64(*d, *f).unwrap_or(Ordering::Equal),
        (Value::Float(f), Value::Decimal(d)) => {
            cmp_decimal_f64(*d, *f).unwrap_or(Ordering::Equal).reverse()
        }
        (Value::Float(x), Value::Float(y)) => x.partial_cmp(y).unwrap_or(Ordering::Equal),
        (Value::Bool(x), Value::Bool(y)) => x.cmp(y),
        (Value::String(x), Value::String(y)) => x.cmp(y),
        (Value::Bytes(x), Value::Bytes(y)) => x.cmp(y),
        (Value::Uuid(x), Value::Uuid(y)) => x.cmp(y),
        // NULLs, arrays, documents: the key encoding's order.
        _ => a.total_cmp(b),
    }
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

/// How many leading components of a key [`note_key_types`] tells the types
/// of: a primary key or an index rarely has more columns, and a position
/// past these is simply not known.
pub const KEY_POSITIONS: usize = 8;

/// Every type at once: what a position holds when it cannot be read.
pub const KEY_TYPES_ANY: u16 = u16::MAX;

/// The bit of the type `tag` keys in a position's set of types.
pub fn key_type_bit(tag: u8) -> u16 {
    1u16.checked_shl(u32::from(tag)).unwrap_or(0)
}

/// Add the type of each leading component of `key` — an order-preserving
/// ARRAY key ([`Value::encode_key`] of a `Value::Array`: a row key
/// `[pk…]`, an index entry `[values…, row key]`) — to `seen`, one set of
/// types per position ([`key_type_bit`]). What a store keeps so that "no
/// key has a float at its second position" is known without looking.
///
/// A set only ever grows, and never says less than the key holds: a
/// component that is itself an array or a document (a nested `0x00` is a
/// null element or the terminator — there is no reliable skip) leaves every
/// position after it holding [`KEY_TYPES_ANY`], and so does a key that is
/// not such an array at all or ends early — from the position where it
/// stops being readable, or from the first for one that is no array.
pub fn note_key_types(key: &[u8], seen: &mut [u16; KEY_POSITIONS]) {
    let unreadable_from = |seen: &mut [u16; KEY_POSITIONS], at: usize| {
        for s in &mut seen[at..] {
            *s = KEY_TYPES_ANY;
        }
    };
    if key.first() != Some(&tag::ARRAY) {
        return unreadable_from(seen, 0);
    }
    let mut pos = 1usize;
    for at in 0..KEY_POSITIONS {
        let Some(&t) = key.get(pos) else {
            return unreadable_from(seen, at);
        };
        pos += 1;
        let skip = match t {
            // The array's own terminator ends the key; anywhere else the
            // byte is a NULL component.
            tag::END if pos == key.len() => return,
            tag::NULL => 0,
            tag::BOOL => 1,
            tag::INT | tag::TIMESTAMP | tag::FLOAT | tag::DECIMAL => 8,
            tag::UUID => 16,
            tag::STRING | tag::BYTES => match skip_escaped_bytes(&key[pos..]) {
                Some(n) => n,
                None => return unreadable_from(seen, at),
            },
            tag::ARRAY | tag::DOCUMENT => {
                seen[at] |= key_type_bit(t);
                return unreadable_from(seen, at + 1);
            }
            _ => return unreadable_from(seen, at),
        };
        pos += skip;
        if pos > key.len() {
            return unreadable_from(seen, at);
        }
        seen[at] |= key_type_bit(t);
    }
}

/// How many components the key prefix `prefix` holds — the position of the
/// component that would follow it. `prefix` is an ARRAY key without its
/// terminator (the array tag and whole scalar components). `None` when it
/// is anything else, or holds a nested array or document.
pub fn key_prefix_positions(prefix: &[u8]) -> Option<usize> {
    if prefix.first() != Some(&tag::ARRAY) {
        return None;
    }
    let (mut pos, mut n) = (1usize, 0usize);
    while pos < prefix.len() {
        let t = prefix[pos];
        pos += 1;
        let skip = match t {
            tag::NULL => 0,
            tag::BOOL => 1,
            tag::INT | tag::TIMESTAMP | tag::FLOAT | tag::DECIMAL => 8,
            tag::UUID => 16,
            tag::STRING | tag::BYTES => skip_escaped_bytes(&prefix[pos..])?,
            _ => return None,
        };
        pos = pos.checked_add(skip)?;
        if pos > prefix.len() {
            return None;
        }
        n += 1;
    }
    Some(n)
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
    /// Arrays / documents nested past `codec::MAX_VALUE_DEPTH`.
    #[error("value nests arrays or documents more than {0} levels deep")]
    TooDeep(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp(a: Value, b: Value) -> Ordering {
        a.total_cmp(&b)
    }

    /// An index entry key and a row key decode back to their scalar
    /// components; anything the encoding cannot give back exactly does not.
    #[test]
    fn scalar_key_tuples_decode_back() {
        let row_key = Value::Array(vec![Value::String("a@b".into()), Value::Int(-7)]).encode_key();
        let entry = vec![
            Value::String("zap\u{0}lski".into()),
            Value::Timestamp(1_700_000_000_123),
            Value::Bool(true),
            Value::Float(-0.0),
            Value::Uuid(Uuid([7u8; 16])),
            Value::Bytes(row_key.clone()),
        ];
        let key = Value::Array(entry.clone()).encode_key();
        let back = decode_scalar_key_tuple(&key).expect("decodes");
        assert_eq!(back.len(), entry.len());
        for (a, b) in back.iter().zip(&entry) {
            assert_eq!(a.encode_key(), b.encode_key(), "{a:?} vs {b:?}");
            assert_eq!(std::mem::discriminant(a), std::mem::discriminant(b));
        }
        assert_eq!(
            decode_scalar_key_tuple(&row_key),
            Some(vec![Value::String("a@b".into()), Value::Int(-7)])
        );
        assert_eq!(decode_scalar_key_tuple(&Value::Array(vec![]).encode_key()), Some(vec![]));
        // NULL (its tag is the terminator), a decimal, a nested array, a
        // bare scalar, a truncated key and trailing bytes all refuse.
        for refused in [
            Value::Array(vec![Value::Null, Value::Bytes(row_key.clone())]).encode_key(),
            Value::Array(vec![Value::Decimal(Decimal::new(125, 2)), Value::Int(1)]).encode_key(),
            Value::Array(vec![Value::Array(vec![Value::Int(1)]), Value::Int(1)]).encode_key(),
            Value::Int(5).encode_key(),
            key[..key.len() - 3].to_vec(),
            [key.as_slice(), &[0u8]].concat(),
        ] {
            assert_eq!(decode_scalar_key_tuple(&refused), None, "{refused:?}");
        }
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
    fn a_decimal_and_a_double_compare_exactly() {
        use Ordering::*;
        let dec = Decimal::new;
        // 0.1 as a double is a little above one tenth, 0.3 a little below
        // three tenths; the halves are exact.
        assert_eq!(cmp_decimal_f64(dec(1, 1), 0.1), Some(Less));
        assert_eq!(cmp_decimal_f64(dec(10, 2), 0.1), Some(Less));
        assert_eq!(cmp_decimal_f64(dec(3, 1), 0.3), Some(Greater));
        assert_eq!(cmp_decimal_f64(dec(5, 1), 0.5), Some(Equal));
        assert_eq!(cmp_decimal_f64(dec(25, 2), 0.25), Some(Equal));
        assert_eq!(cmp_decimal_f64(dec(-5, 1), -0.5), Some(Equal));
        assert_eq!(cmp_decimal_f64(dec(-1, 1), -0.1), Some(Greater));
        assert_eq!(cmp_decimal_f64(dec(-3, 1), -0.3), Some(Less));
        // 2^-20 = 0.00000095367431640625 exactly, twenty digits.
        let tiny = 2f64.powi(-20);
        assert_eq!(cmp_decimal_f64(dec(95_367_431_640_625, 20), tiny), Some(Equal));
        assert_eq!(cmp_decimal_f64(dec(95_367_431_640_624, 20), tiny), Some(Less));
        assert_eq!(cmp_decimal_f64(dec(95_367_431_640_626, 20), tiny), Some(Greater));
        assert_eq!(cmp_decimal_f64(dec(-95_367_431_640_626, 20), -tiny), Some(Less));
        let beside = dec(100_000_000_000_095_367_431_640_625, 20); // 1000000 + 2^-20
        assert_eq!(cmp_decimal_f64(beside, 1_000_000.0 + tiny), Some(Equal));
        assert_eq!(cmp_decimal_f64(beside, 1_000_000.0), Some(Greater));
        // Whole parts decide first, on either side of zero.
        assert_eq!(cmp_decimal_f64(dec(19, 1), 2.1), Some(Less));
        assert_eq!(cmp_decimal_f64(dec(-19, 1), -2.1), Some(Greater));
        assert_eq!(cmp_decimal_f64(dec(5, 1), -0.5), Some(Greater));
        assert_eq!(cmp_decimal_f64(dec(-5, 1), 0.5), Some(Less));
        assert_eq!(cmp_decimal_f64(dec(0, 3), 0.0), Some(Equal));
        assert_eq!(cmp_decimal_f64(dec(0, 3), -0.0), Some(Equal));
        // Past 2^53 a double stands for one integer; the decimal next to it
        // is still another number.
        let two53 = 9_007_199_254_740_992i128;
        assert_eq!(cmp_decimal_f64(dec(two53 + 1, 0), two53 as f64), Some(Greater));
        assert_eq!(cmp_decimal_f64(dec(two53 * 10 + 5, 1), two53 as f64), Some(Greater));
        assert_eq!(cmp_decimal_f64(dec(two53, 0), two53 as f64), Some(Equal));
        // The ends of the mantissa, and of the doubles.
        let two127 = 2f64.powi(127);
        assert_eq!(cmp_decimal_f64(dec(i128::MAX, 0), two127), Some(Less));
        assert_eq!(cmp_decimal_f64(dec(i128::MIN, 0), -two127), Some(Equal));
        assert_eq!(cmp_decimal_f64(dec(i128::MIN, 0), -two127 * 2.0), Some(Greater));
        assert_eq!(cmp_decimal_f64(dec(1, 0), f64::INFINITY), Some(Less));
        assert_eq!(cmp_decimal_f64(dec(1, 0), f64::NEG_INFINITY), Some(Greater));
        assert_eq!(cmp_decimal_f64(dec(1, 0), f64::NAN), None);
        // The smallest double is 4.94065645841246544…e-324.
        let least = f64::from_bits(1);
        assert_eq!(cmp_decimal_f64(dec(49_406_564_584_124_654, 340), least), Some(Less));
        assert_eq!(cmp_decimal_f64(dec(49_406_564_584_124_655, 340), least), Some(Greater));
        assert_eq!(cmp_decimal_f64(dec(1, 1_000), least), Some(Less));
        assert_eq!(cmp_decimal_f64(dec(1, 1_000), 0.0), Some(Greater));
        assert_eq!(cmp_decimal_f64(dec(-1, 4_000_000_000), -least), Some(Greater));
        // 2^127 / 10^361 is still above it, / 10^362 below.
        assert_eq!(cmp_decimal_f64(dec(i128::MAX, 361), least), Some(Greater));
        assert_eq!(cmp_decimal_f64(dec(i128::MAX, 362), least), Some(Less));
        assert_eq!(cmp_decimal_f64(dec(i128::MAX, 400), least), Some(Less));
        assert_eq!(cmp_decimal_f64(dec(i128::MAX, 401), least), Some(Less));
    }

    /// Values a sort may meet in one column of a schema-less table.
    fn sortable_pool() -> Vec<Value> {
        let two53 = 9_007_199_254_740_992i64;
        let ts = 1_700_000_005_000i64;
        let mut pool = vec![Value::Bool(false), Value::Bool(true)];
        for i in [i64::MIN, -two53 - 1, -1, 0, 1, 2, two53, two53 + 1, ts, ts + 1, i64::MAX] {
            pool.push(Value::Int(i));
            pool.push(Value::Timestamp(i));
        }
        for f in [
            f64::NEG_INFINITY,
            -(two53 as f64),
            -0.5,
            -0.0,
            0.0,
            f64::from_bits(1),
            0.1,
            0.3,
            0.5,
            1.0,
            1.5,
            two53 as f64,
            ts as f64 + 0.5,
            1e300,
            f64::INFINITY,
            f64::NAN,
        ] {
            pool.push(Value::Float(f));
        }
        for (m, s) in [
            (0i128, 0u32),
            (1, 1),
            (10, 2),
            (1_000_000_000_000_000_001, 19),
            (3, 1),
            (5, 1),
            (15, 1),
            (i128::from(two53) + 1, 0),
            (i128::from(two53) * 10 + 5, 1),
            (i128::from(ts) * 10 + 5, 1),
            (1, 1_000),
            (-1, 1_000),
            (i128::MAX, 0),
            (i128::MIN, 0),
        ] {
            pool.push(Value::Decimal(Decimal::new(m, s)));
        }
        for s in ["", "2023-11-14", "2023-11-14T22:13:25Z", "2024-01-01T00:00:00Z", "abc", "zzz"] {
            pool.push(Value::String(s.into()));
        }
        pool.push(Value::Bytes(vec![]));
        pool.push(Value::Bytes(vec![0, 1]));
        pool.push(Value::Uuid(Uuid([0u8; 16])));
        pool.push(Value::Uuid(Uuid([7u8; 16])));
        pool.push(Value::Array(vec![]));
        pool.push(Value::Array(vec![Value::Int(1), Value::String("a".into())]));
        let mut doc = Document::new();
        doc.insert("a", Value::Int(1));
        pool.push(Value::Document(Document::new()));
        pool.push(Value::Document(doc));
        pool
    }

    /// `order_cmp` is a total order over everything a column can hold:
    /// antisymmetric and transitive for every triple, which is what a sort
    /// needs to have a result at all.
    #[test]
    fn the_sort_order_is_total() {
        use Ordering::*;
        let pool = sortable_pool();
        for a in &pool {
            assert_eq!(order_cmp(a, a), Equal, "{a:?}");
            for b in &pool {
                let ab = order_cmp(a, b);
                assert_eq!(ab, order_cmp(b, a).reverse(), "{a:?} / {b:?}");
                for c in &pool {
                    let (bc, ac) = (order_cmp(b, c), order_cmp(a, c));
                    if ab != Greater && bc != Greater {
                        assert_ne!(ac, Greater, "{a:?} <= {b:?} <= {c:?}");
                        if ab == Less || bc == Less {
                            assert_eq!(ac, Less, "{a:?} <= {b:?} <= {c:?}, one strictly");
                        }
                    }
                }
            }
        }
        // And the sort itself: every rotation of the pool sorts to one
        // sequence (up to ties) without the library objecting.
        let mut want = pool.clone();
        want.sort_by(order_cmp);
        for shift in 0..pool.len() {
            let mut got = pool.clone();
            got.rotate_left(shift);
            got.reverse();
            got.sort_by(order_cmp);
            for (g, w) in got.iter().zip(&want) {
                assert_eq!(order_cmp(g, w), Equal, "rotation {shift}: {g:?} where {w:?}");
            }
        }
    }

    #[test]
    fn the_sort_order_ranks_numbers_by_value_and_other_types_after() {
        use Ordering::*;
        let dec = |m: i128, s: u32| Value::Decimal(Decimal::new(m, s));
        let s = |x: &str| Value::String(x.into());
        // One number in four types ties; neighbours do not.
        for one in [Value::Int(1), Value::Timestamp(1), Value::Float(1.0), dec(10, 1)] {
            assert_eq!(order_cmp(&one, &Value::Int(1)), Equal, "{one:?}");
            assert_eq!(order_cmp(&one, &Value::Float(1.5)), Less, "{one:?}");
            assert_eq!(order_cmp(&one, &dec(5, 1)), Greater, "{one:?}");
        }
        // A decimal and the double nearest to it are two numbers.
        assert_eq!(order_cmp(&dec(1, 1), &Value::Float(0.1)), Less);
        assert_eq!(order_cmp(&dec(1, 1), &dec(1_000_000_000_000_000_001, 19)), Less);
        // Bools, then every number, then strings — a timestamp is a
        // number, whatever a string spells.
        let ts = Value::Timestamp(1_700_000_005_000);
        assert_eq!(order_cmp(&Value::Bool(true), &Value::Int(i64::MIN)), Less);
        assert_eq!(order_cmp(&ts, &s("2023-11-14T22:13:25Z")), Less);
        assert_eq!(order_cmp(&ts, &s("1999-01-01")), Less);
        assert_eq!(order_cmp(&ts, &s("abc")), Less);
        assert_eq!(order_cmp(&Value::Float(f64::INFINITY), &s("")), Less);
        assert_eq!(order_cmp(&Value::Float(f64::NAN), &Value::Float(f64::INFINITY)), Greater);
        assert_eq!(order_cmp(&Value::Float(f64::NAN), &s("")), Less);
        // Strings as strings, then bytes, uuids, arrays, documents.
        assert_eq!(order_cmp(&s("2024-01-01T00:00:00Z"), &s("abc")), Less);
        assert_eq!(order_cmp(&s("zzz"), &Value::Bytes(vec![])), Less);
        assert_eq!(order_cmp(&Value::Bytes(vec![9]), &Value::Uuid(Uuid([0u8; 16]))), Less);
        assert_eq!(order_cmp(&Value::Uuid(Uuid([9u8; 16])), &Value::Array(vec![])), Less);
        assert_eq!(order_cmp(&Value::Array(vec![]), &Value::Document(Document::new())), Less);
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
    fn decimal_comparison_is_exact() {
        use Ordering::*;
        let d = Decimal::new;
        let two53 = 9_007_199_254_740_992i64;
        // Beyond 2^53 the f64 projection made these equal.
        assert_eq!(cmp_i64_decimal(two53 + 1, d(i128::from(two53), 0)), Greater);
        assert_eq!(cmp_i64_decimal(two53 + 1, d(i128::from(two53 + 1) * 1000, 3)), Equal);
        // Fractions either side of the integer, negative values included.
        assert_eq!(cmp_i64_decimal(1, d(15, 1)), Less);
        assert_eq!(cmp_i64_decimal(2, d(15, 1)), Greater);
        assert_eq!(cmp_i64_decimal(-1, d(-15, 1)), Greater);
        assert_eq!(cmp_i64_decimal(-2, d(-15, 1)), Less);
        assert_eq!(cmp_i64_decimal(0, d(-1, 40)), Greater, "a scale past i128's digits");
        assert_eq!(cmp_i64_decimal(0, d(1, 40)), Less);
        assert_eq!(cmp_i64_decimal(0, d(0, 40)), Equal);
        assert_eq!(cmp_i64_decimal(i64::MAX, d(i128::from(i64::MAX) + 1, 0)), Less);
        assert_eq!(cmp_i64_decimal(i64::MIN, d(i128::from(i64::MIN), 0)), Equal);
        // Decimal against decimal: aligned scales, then the mantissa.
        assert_eq!(cmp_decimal(d(10, 1), d(100, 2)), Equal, "1.0 = 1.00");
        assert_eq!(cmp_decimal(d(1_000_000_000_000_000_001, 18), d(1_000_000_000_000_000_002, 18)), Less);
        assert_eq!(cmp_decimal(d(1, 0), d(1_000_000_000_000_000_001, 18)), Less);
        assert_eq!(cmp_decimal(d(1_000_000_000_000_000_001, 18), d(1, 0)), Greater);
        // A rescale past i128: the sign decides.
        assert_eq!(cmp_decimal(d(5, 0), d(i128::MAX, 40)), Greater);
        assert_eq!(cmp_decimal(d(-5, 0), d(i128::MAX, 40)), Less);
        assert_eq!(cmp_decimal(d(i128::MAX, 40), d(5, 0)), Less);
        // A zero against a scale 10^Δ cannot reach: still zero (it read
        // Equal to anything, so `0 = 5E-40`).
        assert_eq!(cmp_decimal(d(0, 0), d(5, 40)), Less);
        assert_eq!(cmp_decimal(d(5, 40), d(0, 0)), Greater);
        assert_eq!(cmp_decimal(d(0, 0), d(-5, 40)), Greater);
        assert_eq!(cmp_decimal(d(0, 0), d(0, 40)), Equal);
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
    fn equal_decimals_key_alike_however_they_are_spelled() {
        let key = |m: i128, s: u32| Value::Decimal(Decimal::new(m, s)).encode_key();
        // Past 2^53 the mantissa rounds, and the division rounds again.
        let m = 9_007_199_254_740_993i128;
        assert_eq!(key(m, 0), key(m * 10, 1));
        assert_eq!(key(m, 0), key(m * 1000, 3));
        // Past 10^22 the divisor is inexact.
        assert_eq!(key(1, 23), key(10, 24));
        assert_eq!(key(-7, 40), key(-7_000, 43));
        // Every spelling of a sweep of values, against its shortest one.
        let mut x: i128 = 1;
        for i in 0..2_000u32 {
            x = (x * 6_364_136_223_846_793 + 1_442_695_040_888_963) % (1i128 << 62);
            let m = if x % 10 == 0 { x + 1 } else { x };
            let m = if i % 2 == 0 { m } else { -m };
            let scale = i % 30;
            let want = Decimal::new(m, scale).to_f64();
            for k in 0..15u32 {
                let wider = Decimal::new(m * 10i128.pow(k), scale + k);
                assert_eq!(wider.to_f64().to_bits(), want.to_bits(), "{m} scale {scale} +{k}");
            }
        }
    }

    /// An earlier build's key of a value is found from any spelling of it, and
    /// a value no spelling ever moved has none to look for.
    #[test]
    fn earlier_keys_cover_the_spellings_an_earlier_build_divided() {
        let old = |m: i128, s: u32| m as f64 / 10f64.powi(s as i32);
        let short = Decimal::new(9_007_199_254_740_993, 0);
        let long = Decimal::new(90_071_992_547_409_930, 1);
        assert_ne!(old(90_071_992_547_409_930, 1).to_bits(), long.to_f64().to_bits());
        for spelling in [short, long] {
            assert!(spelling.earlier_key_projections().contains(&old(90_071_992_547_409_930, 1)));
            assert!(!spelling.earlier_key_projections().contains(&spelling.to_f64()));
        }
        assert!(Decimal::new(0, 3).earlier_key_projections().is_empty());
        assert!(Decimal::new(15, 1).earlier_key_projections().is_empty());
        assert!(Decimal::new(1_500_000_000_000_000_000, 18).earlier_key_projections().is_empty());

        let (d, i, s) = (Value::Decimal(long), Value::Int(1), Value::String("x".into()));
        assert!(Value::earlier_array_keys(&[&i, &s]).is_empty());
        let keys = Value::earlier_array_keys(&[&i, &d]);
        assert!(!keys.is_empty() && keys.len() <= Value::EARLIER_KEYS_MAX);
        let now = Value::Array(vec![i.clone(), d.clone()]).encode_key();
        assert!(!keys.contains(&now));
        assert!(keys.iter().all(|k| k.len() == now.len()));
        let two = Value::earlier_array_keys(&[&d, &d]);
        assert!(two.len() > keys.len(), "the cross product of two decimals");
    }

    /// Below both limits the projection is what plain division gives, so no
    /// stored key of an ordinary decimal moves.
    #[test]
    fn an_ordinary_decimal_projects_by_plain_division() {
        for (m, s) in [(12_345i128, 2u32), (-1, 0), (150, 2), (1 << 53, 22), (-(1 << 53), 7)] {
            let want = m as f64 / 10f64.powi(s as i32);
            assert_eq!(Decimal::new(m, s).to_f64().to_bits(), want.to_bits());
        }
    }

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

    fn types_of(key: &[u8]) -> [u16; KEY_POSITIONS] {
        let mut seen = [0u16; KEY_POSITIONS];
        note_key_types(key, &mut seen);
        seen
    }

    fn bits(values: &[Value]) -> u16 {
        values.iter().fold(0, |m, v| m | key_type_bit(key_tag(v)))
    }

    #[test]
    fn a_key_tells_the_type_at_each_of_its_positions() {
        let key = pk_key(vec![
            Value::String("a\0b".into()),
            Value::Int(7),
            Value::Float(1.5),
            Value::Timestamp(9),
            Value::Bool(true),
            Value::Uuid(Uuid([3; 16])),
            Value::Bytes(vec![0, 0, 1]),
            Value::Decimal(Decimal::new(15, 1)),
            Value::Int(1), // a ninth component: past what is told
        ]);
        let seen = types_of(&key);
        let want = [
            Value::String(String::new()),
            Value::Int(0),
            Value::Float(0.0),
            Value::Timestamp(0),
            Value::Bool(false),
            Value::Uuid(Uuid([0; 16])),
            Value::Bytes(Vec::new()),
            Value::Decimal(Decimal::new(0, 0)),
        ];
        for (at, v) in want.iter().enumerate() {
            assert_eq!(seen[at], bits(std::slice::from_ref(v)), "position {at}");
        }
        // Sets grow: a second key of other types adds to each position.
        let mut seen = seen;
        note_key_types(&pk_key(vec![Value::Int(1), Value::String("x".into())]), &mut seen);
        assert_eq!(seen[0], bits(&[Value::String(String::new()), Value::Int(0)]));
        assert_eq!(seen[1], bits(&[Value::String(String::new()), Value::Int(0)]));
        assert_eq!(seen[2], bits(&[Value::Float(0.0)]), "a shorter key adds nothing past its end");
        // A NULL component is one byte, and is not the terminator.
        let seen = types_of(&pk_key(vec![Value::Null, Value::Int(1)]));
        assert_eq!((seen[0], seen[1], seen[2]), (bits(&[Value::Null]), bits(&[Value::Int(0)]), 0));
        assert_eq!(types_of(&pk_key(vec![]))[0], 0);
    }

    #[test]
    fn a_key_that_cannot_be_read_holds_every_type_from_there_on() {
        // Not an array at all.
        assert_eq!(types_of(&Value::Int(1).encode_key()), [KEY_TYPES_ANY; KEY_POSITIONS]);
        assert_eq!(types_of(b""), [KEY_TYPES_ANY; KEY_POSITIONS]);
        assert_eq!(types_of(b"t00001/8/1"), [KEY_TYPES_ANY; KEY_POSITIONS]);
        // A nested array: its own position is told, nothing after it.
        let seen = types_of(&pk_key(vec![Value::Int(1), Value::Array(vec![Value::Null]), Value::Int(2)]));
        assert_eq!(seen[0], bits(&[Value::Int(0)]));
        assert_eq!(seen[1], bits(&[Value::Array(Vec::new())]));
        assert!(seen[2..].iter().all(|s| *s == KEY_TYPES_ANY));
        let seen = types_of(&pk_key(vec![Value::Document(Document::new()), Value::Int(2)]));
        assert_eq!(seen[0], bits(&[Value::Document(Document::new())]));
        assert!(seen[1..].iter().all(|s| *s == KEY_TYPES_ANY));
        // Cut short inside a component, and with no terminator.
        let mut cut = pk_key(vec![Value::Int(1), Value::String("abc".into())]);
        cut.truncate(cut.len() - 3);
        let seen = types_of(&cut);
        assert_eq!(seen[0], bits(&[Value::Int(0)]));
        assert!(seen[1..].iter().all(|s| *s == KEY_TYPES_ANY));
        let mut open = pk_key(vec![Value::Int(1)]);
        open.pop();
        let seen = types_of(&open);
        assert_eq!(seen[0], bits(&[Value::Int(0)]));
        assert!(seen[1..].iter().all(|s| *s == KEY_TYPES_ANY));
        // An unknown tag.
        assert_eq!(types_of(&[tag::ARRAY, 0x7f, 0x00]), [KEY_TYPES_ANY; KEY_POSITIONS]);
    }

    #[test]
    fn a_key_prefix_tells_how_many_components_it_holds() {
        let full = pk_key(vec![Value::String("org".into()), Value::Int(7), Value::Bool(true)]);
        assert_eq!(key_prefix_positions(&[tag::ARRAY]), Some(0));
        assert_eq!(key_prefix_positions(encoded_array_prefix(&full, 1).unwrap()), Some(1));
        assert_eq!(key_prefix_positions(encoded_array_prefix(&full, 2).unwrap()), Some(2));
        assert_eq!(key_prefix_positions(&full[..full.len() - 1]), Some(3));
        assert_eq!(key_prefix_positions(b""), None);
        assert_eq!(key_prefix_positions(&Value::Int(1).encode_key()), None);
        // Cut inside a component, or holding a nested array.
        assert_eq!(key_prefix_positions(&full[..3]), None);
        let nested = pk_key(vec![Value::Array(vec![Value::Int(1)]), Value::Int(2)]);
        assert_eq!(key_prefix_positions(&nested[..nested.len() - 1]), None);
    }
}
