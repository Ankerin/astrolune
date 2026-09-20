// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Single-writer atomic archives containing blocks, certificates, and state history.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use state::InMemoryState;
use types::{Block, Hash256};

use crate::{
    Checkpoint, CommitBatch, InMemoryStorage, MAX_ARCHIVE_BYTES, NodeStorage, SnapshotSink,
    SnapshotSource, StorageError, archive,
};

/// Bounded reference chain persistence using synchronized atomic file replacement.
///
/// Rewrites retained history on each update; intended for development and recovery
/// conformance, not production-scale indexing. The operator controls the directory.
#[derive(Debug)]
pub struct FileBackedStorage {
    inner: InMemoryStorage,
    path: PathBuf,
    _lock: File,
    recovery_required: bool,
}

impl FileBackedStorage {
    /// Opens and verifies a chain archive, or atomically creates an empty one.
    ///
    /// The parent directory must exist. `.lock` and `.pending` sidecars are reserved.
    /// Unknown formats and corruption fail closed without replacing existing data.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let requested = path.as_ref();
        let name = requested.file_name().ok_or(StorageError::Io)?;
        let parent = requested
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let path = fs::canonicalize(parent)
            .map_err(|_| StorageError::Io)?
            .join(name);
        for candidate in [&path, &sidecar(&path, ".lock")] {
            if fs::symlink_metadata(candidate).is_ok_and(|m| m.file_type().is_symlink()) {
                return Err(StorageError::Io);
            }
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(sidecar(&path, ".lock"))
            .map_err(|_| StorageError::Io)?;
        lock.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => StorageError::Locked,
            TryLockError::Error(_) => StorageError::Io,
        })?;
        let (inner, create) = match File::open(&path) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take(MAX_ARCHIVE_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| StorageError::Io)?;
                (archive::decode(&bytes)?, false)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                (InMemoryStorage::new(), true)
            }
            Err(_) => return Err(StorageError::Io),
        };
        let mut storage = Self {
            inner,
            path,
            _lock: lock,
            recovery_required: false,
        };
        if create {
            storage.publish(storage.inner.clone())?;
        }
        Ok(storage)
    }

    /// Returns the latest published checkpoint.
    #[must_use]
    pub fn checkpoint(&self) -> Option<&Checkpoint> {
        self.inner.checkpoint()
    }

    /// Returns the latest immutable state view.
    #[must_use]
    pub fn state(&self) -> &InMemoryState {
        self.inner.state()
    }

    /// Returns the number of retained block bodies.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.inner.block_count()
    }

    /// Returns a retained block body.
    #[must_use]
    pub fn get_block(&self, hash: &Hash256) -> Option<&Block> {
        self.inner.get_block(hash)
    }

    /// Returns retained opaque certificate bytes; the caller authenticates finality.
    #[must_use]
    pub fn get_certificate(&self, hash: &Hash256) -> Option<&[u8]> {
        self.inner.get_certificate(hash)
    }

    fn ready(&self) -> Result<(), StorageError> {
        if self.recovery_required {
            Err(StorageError::DurabilityUnknown)
        } else {
            Ok(())
        }
    }

    fn publish(&mut self, next: InMemoryStorage) -> Result<(), StorageError> {
        self.ready()?;
        let bytes = archive::encode(&next)?;
        let temporary = sidecar(&self.path, ".pending");
        match fs::remove_file(&temporary) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(StorageError::Io),
        }
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|_| StorageError::Io)?;
            file.write_all(&bytes).map_err(|_| StorageError::Io)?;
            file.sync_all().map_err(|_| StorageError::Io)?;
            drop(file);
            fs::rename(&temporary, &self.path).map_err(|_| StorageError::Io)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
            return result;
        }
        self.inner = next;
        if sync_parent(&self.path).is_err() {
            self.recovery_required = true;
            return Err(StorageError::DurabilityUnknown);
        }
        Ok(())
    }
}

impl NodeStorage for FileBackedStorage {
    fn recover(&mut self) -> Result<Option<Checkpoint>, StorageError> {
        self.ready()?;
        self.inner.recover()
    }

    fn commit(&mut self, batch: &CommitBatch) -> Result<Checkpoint, StorageError> {
        self.ready()?;
        archive::validate_block(&batch.block, &batch.finality_certificate)?;
        let mut next = self.inner.clone();
        let checkpoint = next.commit(batch)?;
        self.publish(next)?;
        Ok(checkpoint)
    }

    fn export_snapshot(
        &self,
        checkpoint: Checkpoint,
        sink: &mut dyn SnapshotSink,
    ) -> Result<(), StorageError> {
        self.ready()?;
        self.inner.export_snapshot(checkpoint, sink)
    }

    fn import_snapshot(
        &mut self,
        expected: Checkpoint,
        source: &mut dyn SnapshotSource,
    ) -> Result<Checkpoint, StorageError> {
        self.ready()?;
        let mut next = self.inner.clone();
        next.import_snapshot(expected, source)?;
        self.publish(next)?;
        Ok(expected)
    }

    fn prune(&mut self, before_height: u64) -> Result<(), StorageError> {
        self.ready()?;
        let mut next = self.inner.clone();
        next.prune(before_height)?;
        self.publish(next)
    }
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> std::io::Result<()> {
    File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all()
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn sync_parent(_path: &Path) -> std::io::Result<()> {
    Ok(())
}
