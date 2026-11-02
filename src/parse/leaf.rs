use super::ParseError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Final,
    Precert,
}

/// RFC 6962 `TimestampedEntry`. `body` is a certificate for `Final` and a
/// TBSCertificate for `Precert`.
#[derive(Debug, Clone, Copy)]
pub struct TimestampedEntryView<'a> {
    pub timestamp_ms: u64,
    pub kind: EntryKind,
    pub body: &'a [u8],
    pub extensions: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct TileEntry<'a> {
    pub view: TimestampedEntryView<'a>,
    pub pre_certificate: Option<&'a [u8]>,
    pub leaf_index: u64,
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        let end = self.pos.checked_add(n).ok_or(ParseError::Truncated)?;
        let out = self.buf.get(self.pos..end).ok_or(ParseError::Truncated)?;
        self.pos = end;
        Ok(out)
    }
    fn uint(&mut self, n: usize) -> Result<u64, ParseError> {
        Ok(self.take(n)?.iter().fold(0u64, |a, b| (a << 8) | *b as u64))
    }
    fn vec(&mut self, len_bytes: usize) -> Result<&'a [u8], ParseError> {
        let n = self.uint(len_bytes)? as usize;
        self.take(n)
    }
    fn done(&self) -> bool {
        self.pos >= self.buf.len()
    }
}

fn read_entry<'a>(r: &mut Reader<'a>) -> Result<TimestampedEntryView<'a>, ParseError> {
    let timestamp_ms = r.uint(8)?;
    let (kind, body) = match r.uint(2)? {
        0 => (EntryKind::Final, r.vec(3)?),
        1 => {
            r.take(32)?; // issuer_key_hash
            (EntryKind::Precert, r.vec(3)?)
        }
        _ => return Err(ParseError::Unsupported("entry type")),
    };
    let extensions = r.vec(2)?;
    Ok(TimestampedEntryView { timestamp_ms, kind, body, extensions })
}

pub fn decode_timestamped_entry(
    data: &[u8],
) -> Result<(TimestampedEntryView<'_>, usize), ParseError> {
    let mut r = Reader::new(data);
    let v = read_entry(&mut r)?;
    Ok((v, r.pos))
}

pub fn decode_merkle_leaf(data: &[u8]) -> Result<TimestampedEntryView<'_>, ParseError> {
    let mut r = Reader::new(data);
    if r.uint(1)? != 0 {
        return Err(ParseError::Unsupported("leaf version"));
    }
    if r.uint(1)? != 0 {
        return Err(ParseError::Unsupported("leaf type"));
    }
    read_entry(&mut r)
}

/// Finds the static-ct-api `leaf_index` extension: type 0, 5-byte big-endian.
fn leaf_index(extensions: &[u8]) -> Result<u64, ParseError> {
    let mut r = Reader::new(extensions);
    while !r.done() {
        let ty = r.uint(1)?;
        let data = r.vec(2)?;
        if ty == 0 {
            if data.len() != 5 {
                return Err(ParseError::Unsupported("leaf_index length"));
            }
            return Ok(data.iter().fold(0u64, |a, b| (a << 8) | *b as u64));
        }
    }
    Err(ParseError::Unsupported("missing leaf_index"))
}

pub fn decode_tile(data: &[u8]) -> Result<Vec<TileEntry<'_>>, ParseError> {
    let mut r = Reader::new(data);
    let mut out = Vec::with_capacity(256);
    while !r.done() {
        let view = read_entry(&mut r)?;
        let pre_certificate = match view.kind {
            EntryKind::Precert => Some(r.vec(3)?),
            EntryKind::Final => None,
        };
        r.vec(2)?; // certificate_chain fingerprints
        let leaf_index = leaf_index(view.extensions)?;
        out.push(TileEntry { view, pre_certificate, leaf_index });
    }
    Ok(out)
}
