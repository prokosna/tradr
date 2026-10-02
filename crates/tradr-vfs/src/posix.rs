//! POSIX filesystem backend implementing the Layer 1 VFS trait.

use rustix::fd::OwnedFd;
#[cfg(target_os = "linux")]
use rustix::fs::ResolveFlags;
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use rustix::io::Errno;
use std::collections::HashMap;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};
use tradr_core::{
    BoxFuture, DirEntry, EntryKind, Metadata, ReadAt, RelPath, RootId, UnixTime, Vfs, VfsError,
    WriteAt,
};

use crate::sanitization::{
    check_deny_list, check_deny_list_write, is_denied_for_write, partial_root_rel_path,
};

#[derive(Debug, Clone)]
struct RootEntry {
    canonical_path: PathBuf,
    read_only: bool,
}

#[derive(Debug, Clone)]
struct OpenFileEntry {
    file: Arc<std::fs::File>,
    name: String,
}

#[cfg(target_os = "linux")]
static OPENAT2_SUPPORTED: AtomicBool = AtomicBool::new(true);

fn map_rustix_err(err: Errno) -> VfsError {
    match err {
        Errno::NOENT => VfsError::NotFound,
        Errno::XDEV => VfsError::OutsideRoot,
        Errno::LOOP => VfsError::UnsupportedEntry,
        Errno::NOTDIR | Errno::ISDIR | Errno::NOTEMPTY | Errno::EXIST => VfsError::WrongKind,
        Errno::ACCESS | Errno::PERM => VfsError::Io(std::io::ErrorKind::PermissionDenied),
        other => VfsError::Io(std::io::Error::from(other).kind()),
    }
}

fn map_io_err(err: std::io::Error) -> VfsError {
    match err.kind() {
        std::io::ErrorKind::NotFound => VfsError::NotFound,
        std::io::ErrorKind::DirectoryNotEmpty => VfsError::WrongKind,
        other => VfsError::Io(other),
    }
}

fn check_stat_kind(stat: &rustix::fs::Stat) -> Result<EntryKind, VfsError> {
    let ft = FileType::from_raw_mode(stat.st_mode);
    if ft.is_symlink()
        || ft.is_fifo()
        || ft.is_socket()
        || ft.is_char_device()
        || ft.is_block_device()
    {
        return Err(VfsError::UnsupportedEntry);
    }
    if ft.is_dir() {
        Ok(EntryKind::Directory)
    } else if ft.is_file() {
        Ok(EntryKind::File)
    } else {
        Err(VfsError::UnsupportedEntry)
    }
}

fn open_root_dir(root_entry: &RootEntry) -> Result<OwnedFd, VfsError> {
    rustix::fs::open(
        &root_entry.canonical_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(map_rustix_err)
}

fn resolve_and_open_fallback(
    root_fd: &OwnedFd,
    at: &RelPath,
    oflags: OFlags,
    mode: Mode,
) -> Result<OwnedFd, VfsError> {
    let components: Vec<&str> = at.components().collect();
    if components.is_empty() {
        return rustix::fs::openat(root_fd, ".", oflags | OFlags::CLOEXEC, mode)
            .map_err(map_rustix_err);
    }

    let (last, intermediate) = match components.split_last() {
        Some(pair) => pair,
        None => return Err(VfsError::NotFound),
    };

    let mut cur_fd = rustix::fs::openat(
        root_fd,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(map_rustix_err)?;

    for comp in intermediate {
        let next_fd = rustix::fs::openat(
            &cur_fd,
            *comp,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_rustix_err)?;
        cur_fd = next_fd;
    }

    rustix::fs::openat(
        &cur_fd,
        *last,
        oflags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        mode,
    )
    .map_err(map_rustix_err)
}

fn resolve_and_open_entry(
    root_fd: &OwnedFd,
    at: &RelPath,
    oflags: OFlags,
    mode: Mode,
) -> Result<OwnedFd, VfsError> {
    if at.as_str().is_empty() {
        return rustix::fs::openat(root_fd, ".", oflags | OFlags::CLOEXEC, mode)
            .map_err(map_rustix_err);
    }

    #[cfg(target_os = "linux")]
    if OPENAT2_SUPPORTED.load(Ordering::Relaxed) {
        let res = rustix::fs::openat2(
            root_fd,
            at.as_str(),
            oflags | OFlags::CLOEXEC,
            mode,
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        );
        match res {
            Ok(fd) => return Ok(fd),
            Err(Errno::NOSYS) => {
                OPENAT2_SUPPORTED.store(false, Ordering::Relaxed);
            }
            Err(err) => return Err(map_rustix_err(err)),
        }
    }

    resolve_and_open_fallback(root_fd, at, oflags, mode)
}

fn resolve_dir_fd(root_fd: &OwnedFd, components: &[&str]) -> Result<OwnedFd, VfsError> {
    if components.is_empty() {
        return rustix::fs::openat(
            root_fd,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_rustix_err);
    }

    #[cfg(target_os = "linux")]
    if OPENAT2_SUPPORTED.load(Ordering::Relaxed) {
        let subpath = components.join("/");
        let res = rustix::fs::openat2(
            root_fd,
            &subpath,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        );
        match res {
            Ok(fd) => return Ok(fd),
            Err(Errno::NOSYS) => {
                OPENAT2_SUPPORTED.store(false, Ordering::Relaxed);
            }
            Err(err) => return Err(map_rustix_err(err)),
        }
    }

    let mut cur_fd = rustix::fs::openat(
        root_fd,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(map_rustix_err)?;

    for comp in components {
        let next_fd = rustix::fs::openat(
            &cur_fd,
            *comp,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_rustix_err)?;
        cur_fd = next_fd;
    }

    Ok(cur_fd)
}

fn open_read_sync(root: &RootEntry, at: &RelPath) -> Result<std::fs::File, VfsError> {
    check_deny_list(at)?;
    if at.as_str().is_empty() {
        return Err(VfsError::WrongKind);
    }
    let root_fd = open_root_dir(root)?;
    let fd = resolve_and_open_entry(&root_fd, at, OFlags::RDONLY, Mode::empty())?;
    let stat = rustix::fs::fstat(&fd).map_err(map_rustix_err)?;
    let kind = check_stat_kind(&stat)?;
    if kind != EntryKind::File {
        return Err(VfsError::WrongKind);
    }
    Ok(std::fs::File::from(fd))
}

fn open_write_sync(root: &RootEntry, at: &RelPath) -> Result<std::fs::File, VfsError> {
    if root.read_only {
        return Err(VfsError::ReadOnly);
    }
    check_deny_list_write(at)?;
    if at.as_str().is_empty() {
        return Err(VfsError::WrongKind);
    }
    let root_fd = open_root_dir(root)?;
    let fd = resolve_and_open_entry(
        &root_fd,
        at,
        OFlags::RDWR | OFlags::CREATE,
        Mode::from_raw_mode(0o644),
    )?;
    let stat = rustix::fs::fstat(&fd).map_err(map_rustix_err)?;
    let kind = check_stat_kind(&stat)?;
    if kind != EntryKind::File {
        return Err(VfsError::WrongKind);
    }
    Ok(std::fs::File::from(fd))
}

fn stat_sync(root: &RootEntry, at: &RelPath) -> Result<Metadata, VfsError> {
    check_deny_list(at)?;
    let root_fd = open_root_dir(root)?;

    let components: Vec<&str> = at.components().collect();
    let stat = if components.is_empty() {
        rustix::fs::fstat(&root_fd).map_err(map_rustix_err)?
    } else {
        let (target, parent_comps) = components.split_last().unwrap();
        let parent_fd = resolve_dir_fd(&root_fd, parent_comps)?;
        rustix::fs::statat(&parent_fd, *target, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(map_rustix_err)?
    };

    let kind = check_stat_kind(&stat)?;
    let size_bytes = if kind == EntryKind::Directory {
        0
    } else {
        stat.st_size as u64
    };
    let modified = UnixTime::from_secs(stat.st_mtime as i64);
    Ok(Metadata {
        kind,
        size_bytes,
        modified,
    })
}

fn create_dir_sync(root: &RootEntry, at: &RelPath) -> Result<(), VfsError> {
    if root.read_only {
        return Err(VfsError::ReadOnly);
    }
    check_deny_list_write(at)?;
    if at.as_str().is_empty() {
        return Ok(());
    }

    let root_fd = open_root_dir(root)?;
    let components: Vec<&str> = at.components().collect();
    let mut cur_fd = rustix::fs::openat(
        &root_fd,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(map_rustix_err)?;

    for comp in components {
        match rustix::fs::mkdirat(&cur_fd, comp, Mode::from_raw_mode(0o755)) {
            Ok(()) => {}
            Err(Errno::EXIST) => {
                let stat = rustix::fs::statat(&cur_fd, comp, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(map_rustix_err)?;
                let kind = check_stat_kind(&stat)?;
                if kind != EntryKind::Directory {
                    return Err(VfsError::WrongKind);
                }
            }
            Err(err) => return Err(map_rustix_err(err)),
        }

        let next_fd = rustix::fs::openat(
            &cur_fd,
            comp,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_rustix_err)?;
        cur_fd = next_fd;
    }

    Ok(())
}

fn remove_sync(root: &RootEntry, at: &RelPath) -> Result<(), VfsError> {
    if root.read_only {
        return Err(VfsError::ReadOnly);
    }
    check_deny_list_write(at)?;
    if at.as_str().is_empty() {
        return Err(VfsError::WrongKind);
    }

    let root_fd = open_root_dir(root)?;
    let components: Vec<&str> = at.components().collect();
    let (target, parent_comps) = match components.split_last() {
        Some(pair) => pair,
        None => return Err(VfsError::NotFound),
    };
    let parent_fd = resolve_dir_fd(&root_fd, parent_comps)?;

    let stat = rustix::fs::statat(&parent_fd, *target, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(map_rustix_err)?;
    let kind = check_stat_kind(&stat)?;

    match kind {
        EntryKind::Directory => {
            rustix::fs::unlinkat(&parent_fd, *target, AtFlags::REMOVEDIR)
                .map_err(map_rustix_err)?;
        }
        EntryKind::File => {
            rustix::fs::unlinkat(&parent_fd, *target, AtFlags::empty()).map_err(map_rustix_err)?;
        }
    }
    Ok(())
}

enum RenameMode<'a> {
    Replace,
    NoReplace(&'a Mutex<()>),
}

fn rename_internal(
    root: &RootEntry,
    from: &RelPath,
    to: &RelPath,
    mode: RenameMode<'_>,
) -> Result<(), VfsError> {
    if root.read_only {
        return Err(VfsError::ReadOnly);
    }
    check_deny_list_write(from)?;
    check_deny_list(to)?;
    if from.as_str().is_empty() || to.as_str().is_empty() {
        return Err(VfsError::WrongKind);
    }

    let root_fd = open_root_dir(root)?;

    let from_components: Vec<&str> = from.components().collect();
    let (from_target, from_parent_comps) = match from_components.split_last() {
        Some(pair) => pair,
        None => return Err(VfsError::NotFound),
    };
    let from_parent_fd = resolve_dir_fd(&root_fd, from_parent_comps)?;

    let from_stat = rustix::fs::statat(&from_parent_fd, *from_target, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(map_rustix_err)?;
    let _from_kind = check_stat_kind(&from_stat)?;

    let to_components: Vec<&str> = to.components().collect();
    let (to_target, to_parent_comps) = match to_components.split_last() {
        Some(pair) => pair,
        None => return Err(VfsError::NotFound),
    };

    if !to_parent_comps.is_empty() {
        let to_parent_rel = to_parent_comps.join("/");
        if let Ok(rel) = RelPath::new(&to_parent_rel) {
            create_dir_sync(root, &rel)?;
        }
    }

    let to_parent_fd = resolve_dir_fd(&root_fd, to_parent_comps)?;

    match mode {
        RenameMode::Replace => {
            if let Ok(to_stat) =
                rustix::fs::statat(&to_parent_fd, *to_target, AtFlags::SYMLINK_NOFOLLOW)
            {
                check_stat_kind(&to_stat)?;
            }
            rustix::fs::renameat(&from_parent_fd, *from_target, &to_parent_fd, *to_target)
                .map_err(map_rustix_err)?;
        }
        RenameMode::NoReplace(lock) => {
            let _guard = lock
                .lock()
                .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?;
            match rustix::fs::statat(&to_parent_fd, *to_target, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(_) => return Err(VfsError::AlreadyExists),
                Err(Errno::NOENT) => {}
                Err(err) => return Err(map_rustix_err(err)),
            }
            rustix::fs::renameat(&from_parent_fd, *from_target, &to_parent_fd, *to_target)
                .map_err(map_rustix_err)?;
        }
    }
    Ok(())
}

fn rename_sync(root: &RootEntry, from: &RelPath, to: &RelPath) -> Result<(), VfsError> {
    rename_internal(root, from, to, RenameMode::Replace)
}

fn list_dir_sync(root: &RootEntry, at: &RelPath) -> Result<Vec<DirEntry>, VfsError> {
    let root_fd = open_root_dir(root)?;
    let dir_fd = resolve_and_open_entry(
        &root_fd,
        at,
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )?;
    let stat = rustix::fs::fstat(&dir_fd).map_err(map_rustix_err)?;
    let kind = check_stat_kind(&stat)?;
    if kind != EntryKind::Directory {
        return Err(VfsError::WrongKind);
    }

    let mut dir = Dir::read_from(&dir_fd).map_err(map_rustix_err)?;
    let mut entries = Vec::new();
    let parent_components: Vec<&str> = at.components().collect();

    while let Some(entry_res) = dir.read() {
        let entry = entry_res.map_err(map_rustix_err)?;
        let name_bytes = entry.file_name().to_bytes();
        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }
        let name = match std::str::from_utf8(name_bytes) {
            Ok(s) => s.to_string(),
            Err(_) => return Err(VfsError::Io(std::io::ErrorKind::InvalidData)),
        };

        let mut full_components = parent_components.clone();
        full_components.push(&name);
        if is_denied_for_write(&full_components) {
            continue;
        }

        let entry_stat = match rustix::fs::statat(&dir_fd, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(s) => s,
            Err(Errno::NOENT) => continue,
            Err(err) => return Err(map_rustix_err(err)),
        };

        let entry_kind = match check_stat_kind(&entry_stat) {
            Ok(k) => k,
            Err(VfsError::UnsupportedEntry) => continue,
            Err(err) => return Err(err),
        };

        let size_bytes = if entry_kind == EntryKind::Directory {
            0
        } else {
            entry_stat.st_size as u64
        };
        let modified = UnixTime::from_secs(entry_stat.st_mtime as i64);

        entries.push(DirEntry {
            name,
            kind: entry_kind,
            size_bytes,
            modified,
        });
    }

    Ok(entries)
}

fn list_sync(root: &RootEntry, at: &RelPath) -> Result<Vec<DirEntry>, VfsError> {
    check_deny_list(at)?;
    list_dir_sync(root, at)
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

#[derive(Debug)]
struct OpenFileReadHandle {
    file: Arc<std::fs::File>,
}

impl ReadAt for OpenFileReadHandle {
    fn read_at<'a>(
        &'a self,
        offset: u64,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<usize, VfsError>> {
        let file = Arc::clone(&self.file);
        let len = buf.len();
        Box::pin(async move {
            if len == 0 {
                return Ok(0);
            }
            let (res, chunk) = tokio::task::spawn_blocking(move || {
                let mut chunk = vec![0u8; len];
                let res = file.read_at(&mut chunk, offset);
                (res, chunk)
            })
            .await
            .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?;

            let bytes_read = res.map_err(map_io_err)?;
            buf[..bytes_read].copy_from_slice(&chunk[..bytes_read]);
            Ok(bytes_read)
        })
    }
}

fn open_file_metadata(file: &std::fs::File) -> Result<Metadata, VfsError> {
    let meta = file.metadata().map_err(map_io_err)?;
    Ok(Metadata {
        kind: EntryKind::File,
        size_bytes: meta.len(),
        modified: UnixTime::from_secs(meta.mtime()),
    })
}

fn open_file_dir_entry(entry: OpenFileEntry) -> Result<DirEntry, VfsError> {
    let meta = open_file_metadata(&entry.file)?;
    Ok(DirEntry {
        name: entry.name,
        kind: meta.kind,
        size_bytes: meta.size_bytes,
        modified: meta.modified,
    })
}

/// POSIX filesystem implementation enforcing Share Root boundaries.
#[derive(Debug, Default)]
pub struct PosixVfs {
    roots: RwLock<HashMap<u64, RootEntry>>,
    open_files: RwLock<HashMap<u64, OpenFileEntry>>,
    scratch_dir: Option<PathBuf>,
    placement_lock: Arc<Mutex<()>>,
}

impl PosixVfs {
    /// Creates a new, empty POSIX VFS instance.
    pub fn new() -> Self {
        Self {
            roots: RwLock::new(HashMap::new()),
            open_files: RwLock::new(HashMap::new()),
            scratch_dir: None,
            placement_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Configures the directory where anonymous scratch files are created.
    pub fn with_scratch_dir(mut self, dir: PathBuf) -> Self {
        self.scratch_dir = Some(dir);
        self
    }

    /// Allocates an anonymous scratch file for spooling temporary data.
    pub fn scratch_file(&self) -> Result<std::fs::File, VfsError> {
        match &self.scratch_dir {
            Some(dir) => tempfile::tempfile_in(dir),
            None => tempfile::tempfile_in(std::env::temp_dir()),
        }
        .map_err(map_io_err)
    }

    /// An open file the platform handed over becomes a root the sender reads by name,
    /// so no path is ever assembled for it.
    pub fn register_open_file(
        &self,
        root: RootId,
        file: std::fs::File,
        name: &str,
    ) -> Result<(), VfsError> {
        let rel = RelPath::new(name).map_err(|_| VfsError::OutsideRoot)?;
        if rel.components().count() != 1 {
            return Err(VfsError::OutsideRoot);
        }
        let mut roots = self
            .roots
            .write()
            .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?;
        let mut open_files = self
            .open_files
            .write()
            .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?;
        roots.remove(&root.value());
        open_files.insert(
            root.value(),
            OpenFileEntry {
                file: Arc::new(file),
                name: name.to_string(),
            },
        );
        Ok(())
    }

    /// Releases a single-file root so the descriptor closes once active handles finish.
    pub fn unregister_open_file(&self, root: RootId) -> Result<(), VfsError> {
        let mut open_files = self
            .open_files
            .write()
            .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?;
        if open_files.remove(&root.value()).is_some() {
            Ok(())
        } else {
            Err(VfsError::NotFound)
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
        let mut open_files = self
            .open_files
            .write()
            .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?;
        open_files.remove(&root.value());
        roots.insert(
            root.value(),
            RootEntry {
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

    fn get_open_file(&self, root: RootId) -> Result<Option<OpenFileEntry>, VfsError> {
        let open_files = self
            .open_files
            .read()
            .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?;
        Ok(open_files.get(&root.value()).cloned())
    }

    fn has_open_file(&self, root: RootId) -> Result<bool, VfsError> {
        let open_files = self
            .open_files
            .read()
            .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?;
        Ok(open_files.contains_key(&root.value()))
    }

    /// Lists entries in the partial staging root directory (DCR-155).
    pub async fn list_partial_root(&self, root: RootId) -> Result<Vec<DirEntry>, VfsError> {
        if self.has_open_file(root)? {
            return Err(VfsError::WrongKind);
        }
        let root_entry = self.get_root(root)?;
        let at = partial_root_rel_path();
        let res = tokio::task::spawn_blocking(move || list_dir_sync(&root_entry, &at))
            .await
            .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?;
        match res {
            Ok(entries) => Ok(entries),
            Err(VfsError::NotFound) => Ok(Vec::new()),
            Err(err) => Err(err),
        }
    }
}

impl Vfs for PosixVfs {
    fn list<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Vec<DirEntry>, VfsError>> {
        let at = at.clone();
        Box::pin(async move {
            if let Some(entry) = self.get_open_file(root)? {
                if !at.as_str().is_empty() {
                    return Err(VfsError::NotFound);
                }
                let dir_entry = tokio::task::spawn_blocking(move || open_file_dir_entry(entry))
                    .await
                    .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))??;
                return Ok(vec![dir_entry]);
            }
            let root_entry = self.get_root(root)?;
            tokio::task::spawn_blocking(move || list_sync(&root_entry, &at))
                .await
                .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?
        })
    }

    fn stat<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Metadata, VfsError>> {
        let at = at.clone();
        Box::pin(async move {
            if let Some(entry) = self.get_open_file(root)? {
                if at.as_str() != entry.name {
                    return Err(VfsError::NotFound);
                }
                let meta = tokio::task::spawn_blocking(move || open_file_metadata(&entry.file))
                    .await
                    .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))??;
                return Ok(meta);
            }
            let root_entry = self.get_root(root)?;
            tokio::task::spawn_blocking(move || stat_sync(&root_entry, &at))
                .await
                .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?
        })
    }

    fn open_read<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Box<dyn ReadAt>, VfsError>> {
        let at = at.clone();
        Box::pin(async move {
            if let Some(entry) = self.get_open_file(root)? {
                if at.as_str() != entry.name {
                    return Err(VfsError::NotFound);
                }
                let handle: Box<dyn ReadAt> = Box::new(OpenFileReadHandle { file: entry.file });
                return Ok(handle);
            }
            let root_entry = self.get_root(root)?;
            let std_file = tokio::task::spawn_blocking(move || open_read_sync(&root_entry, &at))
                .await
                .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))??;
            let tokio_file = tokio::fs::File::from_std(std_file);
            Ok(Box::new(PosixReadHandle::new(tokio_file)) as Box<dyn ReadAt>)
        })
    }

    fn create_dir<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        let at = at.clone();
        Box::pin(async move {
            if self.has_open_file(root)? {
                return Err(VfsError::ReadOnly);
            }
            let root_entry = self.get_root(root)?;
            tokio::task::spawn_blocking(move || create_dir_sync(&root_entry, &at))
                .await
                .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?
        })
    }

    fn open_write<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Box<dyn WriteAt>, VfsError>> {
        let at = at.clone();
        Box::pin(async move {
            if self.has_open_file(root)? {
                return Err(VfsError::ReadOnly);
            }
            let root_entry = self.get_root(root)?;
            let std_file = tokio::task::spawn_blocking(move || open_write_sync(&root_entry, &at))
                .await
                .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))??;
            let tokio_file = tokio::fs::File::from_std(std_file);
            Ok(Box::new(PosixWriteHandle::new(tokio_file)) as Box<dyn WriteAt>)
        })
    }

    fn rename<'a>(
        &'a self,
        root: RootId,
        from: &'a RelPath,
        to: &'a RelPath,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        let from = from.clone();
        let to = to.clone();
        Box::pin(async move {
            if self.has_open_file(root)? {
                return Err(VfsError::ReadOnly);
            }
            let root_entry = self.get_root(root)?;
            tokio::task::spawn_blocking(move || rename_sync(&root_entry, &from, &to))
                .await
                .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?
        })
    }

    fn rename_no_replace<'a>(
        &'a self,
        root: RootId,
        from: &'a RelPath,
        to: &'a RelPath,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        let from = from.clone();
        let to = to.clone();
        Box::pin(async move {
            if self.has_open_file(root)? {
                return Err(VfsError::ReadOnly);
            }
            let root_entry = self.get_root(root)?;
            let lock = Arc::clone(&self.placement_lock);
            tokio::task::spawn_blocking(move || {
                rename_internal(&root_entry, &from, &to, RenameMode::NoReplace(&lock))
            })
            .await
            .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?
        })
    }

    fn remove<'a>(&'a self, root: RootId, at: &'a RelPath) -> BoxFuture<'a, Result<(), VfsError>> {
        let at = at.clone();
        Box::pin(async move {
            if self.has_open_file(root)? {
                return Err(VfsError::ReadOnly);
            }
            let root_entry = self.get_root(root)?;
            tokio::task::spawn_blocking(move || remove_sync(&root_entry, &at))
                .await
                .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?
        })
    }
}
