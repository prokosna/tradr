//! POSIX filesystem backend implementing the Layer 1 VFS trait.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};
use tradr_core::{
    BoxFuture, DirEntry, EntryKind, Metadata, ReadAt, RelPath, RootId, UnixTime, Vfs, VfsError,
    WriteAt,
};

const DENY_LIST: &[&str] = &[".git", ".ssh", "id_rsa", ".env", ".bash_history"];

#[derive(Debug, Clone)]
struct RootEntry {
    path: PathBuf,
    canonical_path: PathBuf,
    read_only: bool,
}

fn map_io_err(err: std::io::Error) -> VfsError {
    match err.kind() {
        std::io::ErrorKind::NotFound => VfsError::NotFound,
        std::io::ErrorKind::DirectoryNotEmpty => VfsError::WrongKind,
        other => VfsError::Io(other),
    }
}

fn check_deny_list(at: &RelPath) -> Result<(), VfsError> {
    for comp in at.components() {
        if DENY_LIST.contains(&comp) {
            return Err(VfsError::DenyListed);
        }
    }
    Ok(())
}

fn check_unsupported(meta: &std::fs::Metadata) -> Result<EntryKind, VfsError> {
    let ft = meta.file_type();
    if ft.is_symlink() {
        return Err(VfsError::UnsupportedEntry);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if ft.is_fifo() || ft.is_socket() || ft.is_block_device() || ft.is_char_device() {
            return Err(VfsError::UnsupportedEntry);
        }
    }
    if ft.is_dir() {
        Ok(EntryKind::Directory)
    } else if ft.is_file() {
        Ok(EntryKind::File)
    } else {
        Err(VfsError::UnsupportedEntry)
    }
}

fn resolve_path(root: &RootEntry, at: &RelPath) -> Result<PathBuf, VfsError> {
    check_deny_list(at)?;

    let target = if at.as_str().is_empty() {
        root.path.clone()
    } else {
        root.path.join(at.as_str())
    };

    let mut existing = target.clone();
    while !existing.exists() {
        if let Some(parent) = existing.parent() {
            existing = parent.to_path_buf();
        } else {
            break;
        }
    }

    if existing.exists() {
        let canonical = existing.canonicalize().map_err(map_io_err)?;
        if !canonical.starts_with(&root.canonical_path) {
            return Err(VfsError::OutsideRoot);
        }
    }

    if target.exists() {
        let canonical = target.canonicalize().map_err(map_io_err)?;
        if !canonical.starts_with(&root.canonical_path) {
            return Err(VfsError::OutsideRoot);
        }
    }

    Ok(target)
}

fn metadata_to_unix_time(meta: &std::fs::Metadata) -> UnixTime {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| UnixTime::from_secs(d.as_secs() as i64))
        .unwrap_or_else(|| UnixTime::from_secs(0))
}

/// A handle open for positional reads from a POSIX file.
pub struct PosixReadHandle {
    file: tokio::sync::Mutex<tokio::fs::File>,
}

impl PosixReadHandle {
    /// Wraps an open async file handle for reading.
    pub fn new(file: tokio::fs::File) -> Self {
        Self {
            file: tokio::sync::Mutex::new(file),
        }
    }
}

impl ReadAt for PosixReadHandle {
    fn read_at<'a>(
        &'a self,
        offset: u64,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<usize, VfsError>> {
        Box::pin(async move {
            let mut file = self.file.lock().await;
            file.seek(SeekFrom::Start(offset))
                .await
                .map_err(map_io_err)?;
            let n = file.read(buf).await.map_err(map_io_err)?;
            Ok(n)
        })
    }
}

/// A handle open for positional writes to a POSIX file.
pub struct PosixWriteHandle {
    file: tokio::fs::File,
}

impl PosixWriteHandle {
    /// Wraps an open async file handle for writing.
    pub fn new(file: tokio::fs::File) -> Self {
        Self { file }
    }
}

impl WriteAt for PosixWriteHandle {
    fn write_at<'a>(
        &'a mut self,
        offset: u64,
        buf: &'a [u8],
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            self.file
                .seek(SeekFrom::Start(offset))
                .await
                .map_err(map_io_err)?;
            self.file.write_all(buf).await.map_err(map_io_err)?;
            Ok(())
        })
    }

    fn sync<'a>(&'a mut self) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            self.file.flush().await.map_err(map_io_err)?;
            self.file.sync_all().await.map_err(map_io_err)?;
            Ok(())
        })
    }
}

/// POSIX filesystem implementation enforcing Share Root boundaries.
#[derive(Debug, Default)]
pub struct PosixVfs {
    roots: RwLock<HashMap<u64, RootEntry>>,
}

impl PosixVfs {
    /// Creates a new, empty POSIX VFS instance.
    pub fn new() -> Self {
        Self {
            roots: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a filesystem boundary for a given `RootId`.
    pub fn register_root(
        &self,
        root: RootId,
        path: PathBuf,
        read_only: bool,
    ) -> Result<(), VfsError> {
        let canonical_path = path.canonicalize().map_err(map_io_err)?;
        let mut roots = self
            .roots
            .write()
            .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?;
        roots.insert(
            root.value(),
            RootEntry {
                path,
                canonical_path,
                read_only,
            },
        );
        Ok(())
    }

    fn get_root(&self, root: RootId) -> Result<RootEntry, VfsError> {
        let roots = self
            .roots
            .read()
            .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?;
        roots.get(&root.value()).cloned().ok_or(VfsError::NotFound)
    }
}

impl Vfs for PosixVfs {
    fn list<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Vec<DirEntry>, VfsError>> {
        Box::pin(async move {
            let root_entry = self.get_root(root)?;
            let target = resolve_path(&root_entry, at)?;

            let meta = tokio::fs::symlink_metadata(&target)
                .await
                .map_err(map_io_err)?;
            let kind = check_unsupported(&meta)?;
            if kind != EntryKind::Directory {
                return Err(VfsError::WrongKind);
            }

            let mut read_dir = tokio::fs::read_dir(&target).await.map_err(map_io_err)?;
            let mut entries = Vec::new();

            while let Some(entry) = read_dir.next_entry().await.map_err(map_io_err)? {
                let entry_meta = match entry.metadata().await {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let entry_sym_meta = match tokio::fs::symlink_metadata(entry.path()).await {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let entry_kind = match check_unsupported(&entry_sym_meta) {
                    Ok(k) => k,
                    Err(_) => continue,
                };

                let name = entry.file_name().to_string_lossy().into_owned();
                let size_bytes = if entry_kind == EntryKind::Directory {
                    0
                } else {
                    entry_meta.len()
                };
                let modified = metadata_to_unix_time(&entry_meta);

                entries.push(DirEntry {
                    name,
                    kind: entry_kind,
                    size_bytes,
                    modified,
                });
            }

            Ok(entries)
        })
    }

    fn stat<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Metadata, VfsError>> {
        Box::pin(async move {
            let root_entry = self.get_root(root)?;
            let target = resolve_path(&root_entry, at)?;

            let meta = tokio::fs::symlink_metadata(&target)
                .await
                .map_err(map_io_err)?;
            let kind = check_unsupported(&meta)?;
            let size_bytes = if kind == EntryKind::Directory {
                0
            } else {
                meta.len()
            };
            let modified = metadata_to_unix_time(&meta);

            Ok(Metadata {
                kind,
                size_bytes,
                modified,
            })
        })
    }

    fn open_read<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Box<dyn ReadAt>, VfsError>> {
        Box::pin(async move {
            let root_entry = self.get_root(root)?;
            let target = resolve_path(&root_entry, at)?;

            let meta = tokio::fs::symlink_metadata(&target)
                .await
                .map_err(map_io_err)?;
            let kind = check_unsupported(&meta)?;
            if kind != EntryKind::File {
                return Err(VfsError::WrongKind);
            }

            let file = tokio::fs::File::open(&target).await.map_err(map_io_err)?;
            Ok(Box::new(PosixReadHandle::new(file)) as Box<dyn ReadAt>)
        })
    }

    fn create_dir<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let root_entry = self.get_root(root)?;
            if root_entry.read_only {
                return Err(VfsError::ReadOnly);
            }
            let target = resolve_path(&root_entry, at)?;

            if let Ok(meta) = tokio::fs::symlink_metadata(&target).await {
                let kind = check_unsupported(&meta)?;
                if kind == EntryKind::File {
                    return Err(VfsError::WrongKind);
                }
                return Ok(());
            }

            tokio::fs::create_dir_all(&target)
                .await
                .map_err(map_io_err)?;
            Ok(())
        })
    }

    fn open_write<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Box<dyn WriteAt>, VfsError>> {
        Box::pin(async move {
            let root_entry = self.get_root(root)?;
            if root_entry.read_only {
                return Err(VfsError::ReadOnly);
            }
            let target = resolve_path(&root_entry, at)?;

            if let Ok(meta) = tokio::fs::symlink_metadata(&target).await {
                let kind = check_unsupported(&meta)?;
                if kind != EntryKind::File {
                    return Err(VfsError::WrongKind);
                }
            } else if let Some(parent) = target.parent()
                && !parent.exists()
            {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(map_io_err)?;
            }

            let file = tokio::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&target)
                .await
                .map_err(map_io_err)?;

            Ok(Box::new(PosixWriteHandle::new(file)) as Box<dyn WriteAt>)
        })
    }

    fn rename<'a>(
        &'a self,
        root: RootId,
        from: &'a RelPath,
        to: &'a RelPath,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let root_entry = self.get_root(root)?;
            if root_entry.read_only {
                return Err(VfsError::ReadOnly);
            }
            let from_target = resolve_path(&root_entry, from)?;
            let to_target = resolve_path(&root_entry, to)?;

            let meta = tokio::fs::symlink_metadata(&from_target)
                .await
                .map_err(map_io_err)?;
            check_unsupported(&meta)?;

            if let Some(parent) = to_target.parent()
                && !parent.exists()
            {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(map_io_err)?;
            }

            tokio::fs::rename(&from_target, &to_target)
                .await
                .map_err(map_io_err)?;
            Ok(())
        })
    }

    fn remove<'a>(&'a self, root: RootId, at: &'a RelPath) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let root_entry = self.get_root(root)?;
            if root_entry.read_only {
                return Err(VfsError::ReadOnly);
            }
            let target = resolve_path(&root_entry, at)?;

            let meta = tokio::fs::symlink_metadata(&target)
                .await
                .map_err(map_io_err)?;
            let kind = check_unsupported(&meta)?;

            match kind {
                EntryKind::File => {
                    tokio::fs::remove_file(&target).await.map_err(map_io_err)?;
                }
                EntryKind::Directory => {
                    let mut read_dir = tokio::fs::read_dir(&target).await.map_err(map_io_err)?;
                    if read_dir.next_entry().await.map_err(map_io_err)?.is_some() {
                        return Err(VfsError::WrongKind);
                    }
                    tokio::fs::remove_dir(&target).await.map_err(map_io_err)?;
                }
            }
            Ok(())
        })
    }
}
