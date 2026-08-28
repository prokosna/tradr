//! POSIX filesystem backend implementing the Layer 1 VFS trait.

use rustix::fd::OwnedFd;
#[cfg(target_os = "linux")]
use rustix::fs::ResolveFlags;
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use rustix::io::Errno;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};
use tradr_core::{
    BoxFuture, DirEntry, EntryKind, Metadata, ReadAt, RelPath, RootId, UnixTime, Vfs, VfsError,
    WriteAt,
};

// One component of a deny pattern. `Exact` matches a whole component
// case-insensitively; `Glob` matches a component that starts with `prefix`
// and ends with `suffix`, mirroring docs/06's single `*` per pattern.
enum PatternPart {
    Exact(&'static str),
    Glob(&'static str, &'static str),
}

// docs/06-shares-and-linking.md, "The default deny list": the patterns
// below are the whole list and nothing besides. A pattern with more than
// one part denies only that consecutive run of components (DCR-056).
const DENY_PATTERNS: &[&[PatternPart]] = &[
    &[PatternPart::Exact(".tradr-partial")],
    &[PatternPart::Exact(".ssh")],
    &[PatternPart::Exact(".gnupg")],
    &[PatternPart::Exact(".aws")],
    &[PatternPart::Exact(".kube")],
    &[PatternPart::Exact(".config"), PatternPart::Exact("gcloud")],
    &[
        PatternPart::Exact(".docker"),
        PatternPart::Exact("config.json"),
    ],
    &[PatternPart::Exact(".netrc")],
    &[PatternPart::Exact(".git-credentials")],
    &[PatternPart::Exact(".npmrc")],
    &[PatternPart::Exact(".pypirc")],
    &[PatternPart::Glob("", ".pem")],
    &[PatternPart::Glob("", ".key")],
    &[PatternPart::Glob("", ".p12")],
    &[PatternPart::Glob("", ".pfx")],
    &[PatternPart::Glob("", ".keystore")],
    &[PatternPart::Glob("", ".jks")],
    &[PatternPart::Exact(".env")],
    &[PatternPart::Glob(".env.", "")],
    &[PatternPart::Glob("id_rsa", "")],
    &[PatternPart::Glob("id_ed25519", "")],
    &[PatternPart::Glob("id_ecdsa", "")],
];

// ASCII-case-insensitive match of one component against one pattern part.
fn part_matches(part: &PatternPart, component: &str) -> bool {
    match part {
        PatternPart::Exact(pattern) => component.eq_ignore_ascii_case(pattern),
        PatternPart::Glob(prefix, suffix) => {
            let bytes = component.as_bytes();
            if bytes.len() < prefix.len() + suffix.len() {
                return false;
            }
            let head = &bytes[..prefix.len()];
            let tail = &bytes[bytes.len() - suffix.len()..];
            head.eq_ignore_ascii_case(prefix.as_bytes())
                && tail.eq_ignore_ascii_case(suffix.as_bytes())
        }
    }
}

// Whether `pattern` matches some consecutive run of `components`.
fn pattern_matches_run(pattern: &[PatternPart], components: &[&str]) -> bool {
    if components.len() < pattern.len() {
        return false;
    }
    (0..=components.len() - pattern.len()).any(|start| {
        pattern
            .iter()
            .zip(&components[start..start + pattern.len()])
            .all(|(part, comp)| part_matches(part, comp))
    })
}

// DCR-056: denied means neither listed nor reachable, so this is the
// single check both `list` and every other operation route through.
fn is_denied(components: &[&str]) -> bool {
    DENY_PATTERNS
        .iter()
        .any(|pattern| pattern_matches_run(pattern, components))
}

fn is_partial_staging(components: &[&str]) -> bool {
    components.len() > 1
        && matches!(components.first(), Some(c) if c.eq_ignore_ascii_case(".tradr-partial"))
}

fn is_denied_for_write(components: &[&str]) -> bool {
    if is_partial_staging(components) {
        DENY_PATTERNS
            .iter()
            .filter(|p| !matches!(p.first(), Some(PatternPart::Exact(name)) if *name == ".tradr-partial"))
            .any(|pattern| pattern_matches_run(pattern, components))
    } else {
        is_denied(components)
    }
}

#[derive(Debug, Clone)]
struct RootEntry {
    canonical_path: PathBuf,
    read_only: bool,
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

fn check_deny_list(at: &RelPath) -> Result<(), VfsError> {
    let components: Vec<&str> = at.components().collect();
    if is_denied_for_write(&components) {
        return Err(VfsError::DenyListed);
    }
    Ok(())
}

fn check_deny_list_write(at: &RelPath) -> Result<(), VfsError> {
    let components: Vec<&str> = at.components().collect();
    if is_denied_for_write(&components) {
        return Err(VfsError::DenyListed);
    }
    Ok(())
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

fn rename_sync(root: &RootEntry, from: &RelPath, to: &RelPath) -> Result<(), VfsError> {
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

    if let Ok(to_stat) = rustix::fs::statat(&to_parent_fd, *to_target, AtFlags::SYMLINK_NOFOLLOW) {
        check_stat_kind(&to_stat)?;
    }

    rustix::fs::renameat(&from_parent_fd, *from_target, &to_parent_fd, *to_target)
        .map_err(map_rustix_err)?;
    Ok(())
}

fn list_sync(root: &RootEntry, at: &RelPath) -> Result<Vec<DirEntry>, VfsError> {
    check_deny_list(at)?;
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
        if is_denied(&full_components) {
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
        let at = at.clone();
        Box::pin(async move {
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
            let root_entry = self.get_root(root)?;
            tokio::task::spawn_blocking(move || rename_sync(&root_entry, &from, &to))
                .await
                .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?
        })
    }

    fn remove<'a>(&'a self, root: RootId, at: &'a RelPath) -> BoxFuture<'a, Result<(), VfsError>> {
        let at = at.clone();
        Box::pin(async move {
            let root_entry = self.get_root(root)?;
            tokio::task::spawn_blocking(move || remove_sync(&root_entry, &at))
                .await
                .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?
        })
    }
}
