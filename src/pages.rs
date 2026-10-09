//! a database file kept in memory that knows what changed since it was last saved. this is the
//! platform-independent half of the opfs backend, kept apart from the browser bits so it can be
//! tested natively.

use std::collections::BTreeSet;
use std::io;

/// changes are tracked in chunks of this many bytes
const CHUNK: usize = 4096;

#[derive(Debug, Default)]
pub(crate) struct Pages {
    data: Vec<u8>,
    /// chunks written since the last `take_changes`
    dirty: BTreeSet<usize>,
    /// the length of the saved file, as of the last `take_changes`
    saved_len: usize,
    /// the shortest the data has been since the last `take_changes`
    min_len: usize,
}

/// what to do to the saved file so it matches memory, in this order: truncate it to `truncate_to`,
/// extend it with zeros to `len`, then apply `writes`
#[derive(Debug, PartialEq)]
pub(crate) struct Changes {
    pub truncate_to: u64,
    pub len: u64,
    pub writes: Vec<(u64, Vec<u8>)>,
    prev_saved_len: usize,
}

impl Pages {
    /// `data` is what is in the saved file
    pub fn new(data: Vec<u8>) -> Self {
        let len = data.len();
        Self {
            data,
            dirty: BTreeSet::new(),
            saved_len: len,
            min_len: len,
        }
    }

    pub fn len(&self) -> u64 {
        self.data.len() as u64
    }

    pub fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let range = self.range(offset, out.len())?;
        out.copy_from_slice(&self.data[range]);
        Ok(())
    }

    /// new bytes are zeros, as redb expects
    pub fn set_len(&mut self, len: u64) -> io::Result<()> {
        let len = usize::try_from(len).map_err(|_| out_of_range())?;
        self.data.resize(len, 0);
        self.min_len = self.min_len.min(len);
        Ok(())
    }

    pub fn write(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        let range = self.range(offset, data.len())?;
        if !data.is_empty() {
            self.dirty.extend(range.start / CHUNK..=(range.end - 1) / CHUNK);
        }
        self.data[range].copy_from_slice(data);
        Ok(())
    }

    /// everything that changed since the last call, or `None` if nothing did. the changes are
    /// considered saved from now on, `restore` them if saving fails.
    pub fn take_changes(&mut self) -> Option<Changes> {
        let len = self.data.len();
        if self.dirty.is_empty() && self.saved_len == len && self.min_len == len {
            return None;
        }

        let mut writes: Vec<(u64, Vec<u8>)> = vec![];
        let mut run: Option<(usize, usize)> = None;
        for chunk in std::mem::take(&mut self.dirty) {
            run = match run {
                Some((start, end)) if end == chunk => Some((start, chunk + 1)),
                _ => {
                    if let Some(r) = run {
                        self.push_run(&mut writes, r);
                    }
                    Some((chunk, chunk + 1))
                }
            };
        }
        if let Some(r) = run {
            self.push_run(&mut writes, r);
        }

        let changes = Changes {
            // bytes the saved file has past the shortest length must not come back as garbage
            truncate_to: self.min_len.min(self.saved_len) as u64,
            len: len as u64,
            writes,
            prev_saved_len: self.saved_len,
        };
        self.saved_len = len;
        self.min_len = len;
        Some(changes)
    }

    /// saving `changes` failed: they are still to be saved
    pub fn restore(&mut self, changes: Changes) {
        for (offset, bytes) in &changes.writes {
            let start = *offset as usize / CHUNK;
            let end = (*offset as usize + bytes.len()).div_ceil(CHUNK);
            self.dirty
                .extend((start..end).filter(|c| c * CHUNK < self.data.len()));
        }
        self.saved_len = changes.prev_saved_len;
        self.min_len = self.min_len.min(changes.truncate_to as usize);
    }

    fn push_run(&self, writes: &mut Vec<(u64, Vec<u8>)>, (start, end): (usize, usize)) {
        let start = start * CHUNK;
        let end = (end * CHUNK).min(self.data.len());
        if start < end {
            writes.push((start as u64, self.data[start..end].to_vec()));
        }
    }

    fn range(&self, offset: u64, len: usize) -> io::Result<std::ops::Range<usize>> {
        let start = usize::try_from(offset).map_err(|_| out_of_range())?;
        let end = start.checked_add(len).ok_or_else(out_of_range)?;
        if end > self.data.len() {
            return Err(out_of_range());
        }
        Ok(start..end)
    }
}

fn out_of_range() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "index out-of-range")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// applies changes the way the opfs backend does, to a plain vec standing for the file
    fn apply(file: &mut Vec<u8>, changes: &Changes) {
        file.truncate(changes.truncate_to as usize);
        file.resize(changes.len as usize, 0);
        for (offset, bytes) in &changes.writes {
            file[*offset as usize..*offset as usize + bytes.len()].copy_from_slice(bytes);
        }
    }

    #[test]
    fn saves_only_what_changed() {
        let mut p = Pages::new(vec![1; 5 * CHUNK]);
        assert_eq!(p.take_changes(), None);

        p.write(10, &[2, 2]).unwrap();
        p.write(CHUNK as u64 - 1, &[3, 3]).unwrap();
        p.write(4 * CHUNK as u64, &[4]).unwrap();
        let c = p.take_changes().unwrap();
        // chunks 0 and 1 merge, chunk 4 is alone
        assert_eq!(c.writes.len(), 2);
        assert_eq!(c.writes[0].0, 0);
        assert_eq!(c.writes[0].1.len(), 2 * CHUNK);
        assert_eq!(c.writes[1].0, 4 * CHUNK as u64);
        assert_eq!(p.take_changes(), None);
    }

    #[test]
    fn the_file_always_ends_up_like_memory() {
        let mut file = vec![7u8; 3 * CHUNK + 100];
        let mut p = Pages::new(file.clone());

        // shrink and grow back: the regrown part must be zeros, not what the file had there
        p.set_len(CHUNK as u64).unwrap();
        p.set_len(4 * CHUNK as u64).unwrap();
        p.write(3 * CHUNK as u64, &[9; 10]).unwrap();
        apply(&mut file, &p.take_changes().unwrap());
        let mut mem = vec![0; p.len() as usize];
        p.read(0, &mut mem).unwrap();
        assert_eq!(file, mem);

        // a write past the end of a shrunk file is dropped
        p.write(3 * CHUNK as u64, &[5; 10]).unwrap();
        p.set_len(2 * CHUNK as u64 + 3).unwrap();
        let c = p.take_changes().unwrap();
        assert!(c.writes.is_empty());
        apply(&mut file, &c);
        assert_eq!(file.len(), 2 * CHUNK + 3);
        assert_eq!(&file[..CHUNK], &[7; CHUNK]);
        assert_eq!(&file[CHUNK..], &vec![0; CHUNK + 3][..]);
    }

    #[test]
    fn failed_saves_are_retried() {
        let mut file = vec![0u8; 2 * CHUNK];
        let mut p = Pages::new(file.clone());
        p.write(5, &[1]).unwrap();
        p.set_len(CHUNK as u64).unwrap();
        let failed = p.take_changes().unwrap();
        p.restore(failed);

        p.write(6, &[2]).unwrap();
        apply(&mut file, &p.take_changes().unwrap());
        let mut mem = vec![0; p.len() as usize];
        p.read(0, &mut mem).unwrap();
        assert_eq!(file, mem);
        assert_eq!(&file[5..7], &[1, 2]);
    }

    #[test]
    fn bounds() {
        let mut p = Pages::new(vec![0; 10]);
        assert!(p.read(5, &mut [0; 6]).is_err());
        assert!(p.write(10, &[1]).is_err());
        assert!(p.write(u64::MAX, &[1]).is_err());
        p.write(10, &[]).unwrap();
    }
}
