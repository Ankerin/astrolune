// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Append-only, exclusively locked reference signing journal.

use crate::{KeystoreError, PRECOMMIT_PHASE, SigningContext, SigningPosition};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use types::{Hash256, hash::domain_hash};

const HEADER_BYTES: usize = 108;
const RECORD_BYTES: usize = 85;
const HEADER_DOMAIN: &[u8] = b"astrolune.signing.journal.v1";
const RECORD_DOMAIN: &[u8] = b"astrolune.signing.decision.v1";

/// Maximum durable decisions; no automatic pruning or reset is permitted.
pub const MAX_JOURNAL_RECORDS: u64 = 100_000;
/// Maximum reference journal size, including its header and chained checksums.
pub const MAX_JOURNAL_BYTES: u64 = HEADER_BYTES as u64 + RECORD_BYTES as u64 * MAX_JOURNAL_RECORDS;

pub(crate) struct Journal {
    file: File,
    count: u64,
    tip: Hash256,
    last: Option<(SigningPosition, Hash256)>,
    poisoned: bool,
}

fn header(context: SigningContext, public_key: [u8; 32]) -> [u8; HEADER_BYTES] {
    let mut bytes = [0; HEADER_BYTES];
    bytes[..4].copy_from_slice(b"ALSJ");
    bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&context.chain_id.to_le_bytes());
    bytes[12..44].copy_from_slice(&context.genesis.0);
    bytes[44..76].copy_from_slice(&public_key);
    let checksum = domain_hash(HEADER_DOMAIN, &bytes[..76]);
    bytes[76..].copy_from_slice(&checksum.0);
    bytes
}

fn record(
    sequence: u64,
    position: SigningPosition,
    message: Hash256,
    tip: Hash256,
) -> [u8; RECORD_BYTES] {
    let mut bytes = [0; RECORD_BYTES];
    bytes[..8].copy_from_slice(&sequence.to_le_bytes());
    bytes[8..16].copy_from_slice(&position.height.to_le_bytes());
    bytes[16..20].copy_from_slice(&position.round.to_le_bytes());
    bytes[20] = position.phase;
    bytes[21..53].copy_from_slice(&message.0);
    let checksum = record_hash(tip, &bytes[..53]);
    bytes[53..].copy_from_slice(&checksum.0);
    bytes
}

fn record_hash(tip: Hash256, body: &[u8]) -> Hash256 {
    let mut input = [0; 85];
    input[..32].copy_from_slice(&tip.0);
    input[32..].copy_from_slice(body);
    domain_hash(RECORD_DOMAIN, &input)
}

fn decode_record(
    bytes: &[u8; RECORD_BYTES],
    sequence: u64,
    tip: Hash256,
) -> Result<(SigningPosition, Hash256, Hash256), KeystoreError> {
    let mut decoder = codec::Decoder::new(bytes);
    let fields = (|| -> Result<_, codec::DecodeError> {
        let sequence = decoder.read_u64()?;
        let position = SigningPosition {
            height: decoder.read_u64()?,
            round: decoder.read_u32()?,
            phase: decoder.read_u8()?,
        };
        let message = Hash256(decoder.read_fixed()?);
        let checksum = Hash256(decoder.read_fixed()?);
        decoder.finish()?;
        Ok((sequence, position, message, checksum))
    })()
    .map_err(|_| KeystoreError::InvalidJournal)?;
    if fields.0 != sequence
        || fields.1.phase > PRECOMMIT_PHASE
        || fields.3 != record_hash(tip, &bytes[..53])
    {
        return Err(KeystoreError::InvalidJournal);
    }
    Ok((fields.1, fields.2, fields.3))
}

fn canonical_path(path: &Path) -> Result<PathBuf, KeystoreError> {
    let name = path.file_name().ok_or(KeystoreError::JournalFailure)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let path = fs::canonicalize(parent)
        .map_err(|_| KeystoreError::JournalFailure)?
        .join(name);
    if fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(KeystoreError::InvalidJournal);
    }
    Ok(path)
}

fn lock(file: &File) -> Result<(), KeystoreError> {
    file.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => KeystoreError::Locked,
        TryLockError::Error(_) => KeystoreError::JournalFailure,
    })
}

// Unix synchronizes the directory entry on create. Windows power-loss durability
// depends on the filesystem; existing journal updates synchronize the same file.
#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
fn sync_parent(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

impl Journal {
    pub(crate) fn create(
        path: &Path,
        context: SigningContext,
        public_key: [u8; 32],
    ) -> Result<Self, KeystoreError> {
        let path = canonical_path(path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    KeystoreError::AlreadyExists
                } else {
                    KeystoreError::JournalFailure
                }
            })?;
        lock(&file)?;
        let bytes = header(context, public_key);
        // Failure leaves the file in place: never silently reset an interrupted create.
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .and_then(|()| sync_parent(&path))
            .map_err(|_| KeystoreError::JournalFailure)?;
        Ok(Self {
            file,
            count: 0,
            tip: domain_hash(HEADER_DOMAIN, &bytes[..76]),
            last: None,
            poisoned: false,
        })
    }

    pub(crate) fn open(
        path: &Path,
        context: SigningContext,
        public_key: [u8; 32],
    ) -> Result<Self, KeystoreError> {
        let path = canonical_path(path)?;
        // Never creates a missing journal, even if the key is available.
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&path)
            .map_err(|_| KeystoreError::JournalFailure)?;
        lock(&file)?;
        let metadata = file.metadata().map_err(|_| KeystoreError::JournalFailure)?;
        let length = metadata.len();
        if !metadata.is_file()
            || !(HEADER_BYTES as u64..=MAX_JOURNAL_BYTES).contains(&length)
            || !(length - HEADER_BYTES as u64).is_multiple_of(RECORD_BYTES as u64)
        {
            return Err(KeystoreError::InvalidJournal);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| KeystoreError::JournalFailure)?;
        let mut bytes = [0; HEADER_BYTES];
        file.read_exact(&mut bytes)
            .map_err(|_| KeystoreError::InvalidJournal)?;
        let checksum = domain_hash(HEADER_DOMAIN, &bytes[..76]);
        if &bytes[..4] != b"ALSJ" || bytes[4..8] != 1u32.to_le_bytes() || bytes[76..] != checksum.0
        {
            return Err(KeystoreError::InvalidJournal);
        }
        if bytes != header(context, public_key) {
            return Err(KeystoreError::ContextMismatch);
        }
        let count = (length - HEADER_BYTES as u64) / RECORD_BYTES as u64;
        let mut journal = Self {
            file,
            count,
            tip: checksum,
            last: None,
            poisoned: false,
        };
        for sequence in 1..=count {
            let mut bytes = [0; RECORD_BYTES];
            journal
                .file
                .read_exact(&mut bytes)
                .map_err(|_| KeystoreError::InvalidJournal)?;
            let (position, message, tip) = decode_record(&bytes, sequence, journal.tip)?;
            if journal
                .last
                .is_some_and(|(previous, _)| position <= previous)
            {
                return Err(KeystoreError::InvalidJournal);
            }
            journal.last = Some((position, message));
            journal.tip = tip;
        }
        journal.check_length()?;
        // A preceding failed sync may have left a complete record in the OS cache.
        // Re-establish durability before allowing even an idempotent signature retry.
        journal
            .file
            .sync_all()
            .and_then(|()| sync_parent(&path))
            .map_err(|_| KeystoreError::JournalFailure)?;
        Ok(journal)
    }

    pub(crate) const fn last_position(&self) -> Option<SigningPosition> {
        match self.last {
            Some((position, _)) => Some(position),
            None => None,
        }
    }

    fn check_length(&mut self) -> Result<(), KeystoreError> {
        let expected = HEADER_BYTES as u64 + self.count * RECORD_BYTES as u64;
        if !self
            .file
            .metadata()
            .is_ok_and(|metadata| metadata.len() == expected)
        {
            self.poisoned = true;
            return Err(KeystoreError::InvalidJournal);
        }
        Ok(())
    }

    pub(crate) fn reserve(
        &mut self,
        position: SigningPosition,
        message: Hash256,
    ) -> Result<(), KeystoreError> {
        self.reserve_with(position, message, |file, bytes| {
            file.write_all(bytes)?;
            file.sync_all()
        })
    }

    fn reserve_with(
        &mut self,
        position: SigningPosition,
        message: Hash256,
        persist: impl FnOnce(&mut File, &[u8]) -> std::io::Result<()>,
    ) -> Result<(), KeystoreError> {
        if self.poisoned {
            return Err(KeystoreError::DurabilityUnknown);
        }
        if position.phase > PRECOMMIT_PHASE {
            return Err(KeystoreError::InvalidPosition);
        }
        self.check_length()?;
        if let Some((previous, digest)) = self.last {
            if position < previous {
                return Err(KeystoreError::StalePosition);
            }
            if position == previous {
                return if message == digest {
                    Ok(())
                } else {
                    Err(KeystoreError::ConflictingSign)
                };
            }
        }
        if self.count == MAX_JOURNAL_RECORDS {
            return Err(KeystoreError::LimitExceeded);
        }
        let bytes = record(self.count + 1, position, message, self.tip);
        // Any uncertain write poisons this instance. No signature can escape until
        // reopening validates the complete prefix and synchronizes it successfully.
        self.poisoned = true;
        persist(&mut self.file, &bytes).map_err(|_| KeystoreError::DurabilityUnknown)?;
        self.last = Some((position, message));
        self.tip = record_hash(self.tip, &bytes[..53]);
        self.count += 1;
        self.poisoned = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "astrolune-journal-fault-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> PathBuf {
            self.0.join("journal.bin")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn context() -> SigningContext {
        SigningContext {
            chain_id: 7,
            genesis: Hash256([8; 32]),
        }
    }
    fn position(height: u64) -> SigningPosition {
        SigningPosition {
            height,
            round: 5,
            phase: 1,
        }
    }

    #[test]
    fn checksums_match_independent_python_blake2s_vectors() {
        let bytes = header(context(), [9; 32]);
        let tip = domain_hash(HEADER_DOMAIN, &bytes[..76]);
        assert_eq!(
            tip.to_string(),
            "d4bd91c229f50b736d91fd2031492b4a56b2e36dc98003cbe5643c5cff62e25d"
        );
        assert_eq!(&bytes[..12], &[65, 76, 83, 74, 1, 0, 0, 0, 7, 0, 0, 0]);
        let bytes = record(1, position(42), Hash256([6; 32]), tip);
        let (coordinate, digest, checksum) = decode_record(&bytes, 1, tip).unwrap();
        assert_eq!(coordinate, position(42));
        assert_eq!(digest, Hash256([6; 32]));
        assert_eq!(
            checksum.to_string(),
            "e39464bfed981fb45c77d2a76ca71b4ab005cfe3fbde1056554b072ba486566d"
        );
    }

    #[test]
    fn uncertain_writes_poison_signing_and_recovery_preserves_complete_decisions() {
        for written in [0, 12, RECORD_BYTES] {
            let fixture = Fixture::new();
            let mut journal = Journal::create(&fixture.path(), context(), [9; 32]).unwrap();
            let result = journal.reserve_with(position(42), Hash256([6; 32]), |file, bytes| {
                file.write_all(&bytes[..written])?;
                // Model failure before append, during append, or at synchronization.
                Err(std::io::Error::other("injected persistence failure"))
            });
            assert_eq!(result, Err(KeystoreError::DurabilityUnknown));
            assert_eq!(
                journal.reserve(position(42), Hash256([6; 32])),
                Err(KeystoreError::DurabilityUnknown)
            );
            assert_eq!(
                journal.reserve(position(43), Hash256([7; 32])),
                Err(KeystoreError::DurabilityUnknown)
            );
            drop(journal);
            let before = fs::read(fixture.path()).unwrap();
            let recovered = Journal::open(&fixture.path(), context(), [9; 32]);
            if written == 12 {
                assert!(matches!(recovered, Err(KeystoreError::InvalidJournal)));
            } else {
                let mut recovered = recovered.unwrap();
                if written == RECORD_BYTES {
                    assert_eq!(recovered.last_position(), Some(position(42)));
                    recovered.reserve(position(42), Hash256([6; 32])).unwrap();
                    assert_eq!(
                        recovered.reserve(position(42), Hash256([7; 32])),
                        Err(KeystoreError::ConflictingSign)
                    );
                } else {
                    assert_eq!(recovered.last_position(), None);
                }
            }
            assert_eq!(fs::read(fixture.path()).unwrap(), before);
        }
    }

    #[test]
    fn valid_checksums_do_not_allow_reordered_duplicate_or_invalid_coordinates() {
        let fixture = Fixture::new();
        let initial = header(context(), [9; 32]);
        let tip = domain_hash(HEADER_DOMAIN, &initial[..76]);
        let first = record(1, position(42), Hash256([6; 32]), tip);
        let tip = record_hash(tip, &first[..53]);
        for (sequence, next) in [
            (1, position(43)),
            (3, position(43)),
            (2, position(41)),
            (2, position(42)),
            (
                2,
                SigningPosition {
                    phase: 255,
                    ..position(43)
                },
            ),
        ] {
            let second = record(sequence, next, Hash256([7; 32]), tip);
            let bytes = [initial.as_slice(), first.as_slice(), second.as_slice()].concat();
            fs::write(fixture.path(), &bytes).unwrap();
            assert!(matches!(
                Journal::open(&fixture.path(), context(), [9; 32]),
                Err(KeystoreError::InvalidJournal)
            ));
            assert_eq!(fs::read(fixture.path()).unwrap(), bytes);
        }
    }

    #[test]
    fn full_journal_halts_new_signing_and_unexpected_length_poisons_the_session() {
        let fixture = Fixture::new();
        let mut journal = Journal::create(&fixture.path(), context(), [9; 32]).unwrap();
        journal
            .file
            .write_all(&vec![
                0;
                usize::try_from(MAX_JOURNAL_BYTES).unwrap()
                    - HEADER_BYTES
            ])
            .unwrap();
        journal.count = MAX_JOURNAL_RECORDS;
        journal.last = Some((position(42), Hash256([6; 32])));
        assert_eq!(
            journal.reserve(position(43), Hash256([6; 32])),
            Err(KeystoreError::LimitExceeded)
        );
        journal.reserve(position(42), Hash256([6; 32])).unwrap();
        journal.file.write_all(&[0]).unwrap();
        assert_eq!(
            journal.reserve(position(42), Hash256([6; 32])),
            Err(KeystoreError::InvalidJournal)
        );
        assert_eq!(
            journal.reserve(position(43), Hash256([6; 32])),
            Err(KeystoreError::DurabilityUnknown)
        );
    }
}
