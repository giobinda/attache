use std::collections::HashMap;
use std::ffi::{CString, OsStr};
use std::fs::{self, File, OpenOptions};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use filetime::FileTime;
use fuser::{
    BsdFileFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation,
    INodeNo, LockOwner, OpenAccMode, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow,
    WriteFlags,
};

use crate::inode_table::InodeTable;
use crate::policy::{AuthPolicy, Decision, Prompter};
use crate::process_info::ProcessResolver;
use crate::whitelist::{Whitelist, WHITELIST_FILENAME};

const TTL: Duration = Duration::from_secs(1);

/// True for any path whose final component is the vault's whitelist file,
/// regardless of which directory it's in. `PassthroughFs` refuses all FUSE
/// access to such paths unconditionally — including to a caller that has
/// already been granted vault access — so the whitelist can only ever be
/// read or modified by this gate process operating on the backing
/// directory directly, never through the mounted vault itself.
fn is_protected(path: &std::path::Path) -> bool {
    path.file_name() == Some(OsStr::new(WHITELIST_FILENAME))
}

/// Unix-epoch seconds now, saturating to 0 if the clock is before the
/// epoch (it isn't).
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A read-only view of vault activity for the control socket
/// (`control.rs`), so `att`'s idle-timeout manager can ask the running
/// gate "is anything actually using the vault right now?" rather than
/// sampling `lsof`/mtime from outside the mount. An outside sample misses
/// a media player that opened a track, buffered it, and closed the fd
/// between two of the manager's 5-minutely checks - which used to get the
/// vault torn down mid-playlist.
#[derive(Clone)]
pub struct ActivityMonitor {
    last_activity: Arc<AtomicU64>,
    handles: Arc<Mutex<HashMap<u64, Arc<File>>>>,
}

impl ActivityMonitor {
    /// Unix-epoch seconds of the most recent `open`/`create`/`read`/`write`
    /// through the mount. Initialised to mount time, so a vault nobody has
    /// touched yet still reports a sane "idle for N seconds".
    pub fn last_activity_secs(&self) -> u64 {
        self.last_activity.load(Ordering::Relaxed)
    }

    /// How many file handles are open in the vault right now. Non-zero
    /// means some process is holding a file open (an editor with a buffer,
    /// a player mid-track) even if no read/write has crossed the gate
    /// within the idle window.
    pub fn open_handles(&self) -> usize {
        self.handles.lock().unwrap().len()
    }
}

/// A FUSE filesystem that transparently forwards every operation to
/// `backing_root`, except that `open`/`create`/`setattr` are gated behind
/// an [`AuthPolicy`] decision keyed on the calling process's binary.
pub struct PassthroughFs<P: Prompter, R: ProcessResolver> {
    inodes: Mutex<InodeTable>,
    // `Arc<File>` (not `File`) so `read`/`write` can clone the handle out
    // under the lock and then do the backing I/O with the lock released -
    // otherwise every read/write in the vault serialises through this one
    // mutex for the whole duration of a gocryptfs-backed transfer.
    // `Arc<Mutex<..>>` (not a bare `Mutex`) so `ActivityMonitor` can read
    // the live handle count over the control socket.
    handles: Arc<Mutex<HashMap<u64, Arc<File>>>>,
    next_fh: AtomicU64,
    // Bumped to `now_secs()` on every gated `open`/`create` and every
    // `read`/`write` that moves bytes. `att`'s idle check reads this via
    // the control socket instead of guessing from `lsof`/mtime.
    last_activity: Arc<AtomicU64>,
    auth: AuthPolicy<P>,
    resolver: R,
}

impl<P: Prompter, R: ProcessResolver> PassthroughFs<P, R> {
    pub fn new(backing_root: PathBuf, prompter: P, resolver: R) -> Self {
        let whitelist = Whitelist::load(&backing_root);
        Self {
            inodes: Mutex::new(InodeTable::new(backing_root)),
            handles: Arc::new(Mutex::new(HashMap::new())),
            next_fh: AtomicU64::new(1),
            last_activity: Arc::new(AtomicU64::new(now_secs())),
            auth: AuthPolicy::new(prompter, whitelist),
            resolver,
        }
    }

    /// A read-only activity view for the control socket (`control.rs`),
    /// backing `att`'s idle-timeout check.
    pub fn activity_monitor(&self) -> ActivityMonitor {
        ActivityMonitor {
            last_activity: Arc::clone(&self.last_activity),
            handles: Arc::clone(&self.handles),
        }
    }

    /// Records "the vault was just used" for the idle timeout. Cheap
    /// enough (one relaxed atomic store) to call on every read/write.
    fn mark_activity(&self) {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
    }

    /// A shared handle to this mount's whitelist, for the control socket
    /// (`control.rs`) to mutate from outside the normal FUSE request path
    /// while the mount is live.
    pub fn whitelist_handle(&self) -> std::sync::Arc<std::sync::Mutex<crate::whitelist::Whitelist>> {
        self.auth.whitelist_handle()
    }

    fn path_of(&self, ino: INodeNo) -> Option<PathBuf> {
        self.inodes.lock().unwrap().path(ino)
    }

    fn alloc_fh(&self) -> u64 {
        self.next_fh.fetch_add(1, Ordering::SeqCst)
    }

    /// Resolves the calling process and asks the auth policy whether it may
    /// touch `target`. Fails closed (denies) if the process can't be
    /// resolved at all.
    fn authorize(&self, req: &Request, target: &std::path::Path) -> bool {
        match self.resolver.resolve(req.pid()) {
            Some(identity) => self.auth.decide(&identity, target) == Decision::Allow,
            None => false,
        }
    }
}

fn attr_from_metadata(ino: INodeNo, meta: &fs::Metadata) -> FileAttr {
    let kind = if meta.is_dir() {
        FileType::Directory
    } else if meta.file_type().is_symlink() {
        FileType::Symlink
    } else {
        FileType::RegularFile
    };
    FileAttr {
        ino,
        size: meta.size(),
        blocks: meta.blocks(),
        atime: meta.accessed().unwrap_or(UNIX_EPOCH),
        mtime: meta.modified().unwrap_or(UNIX_EPOCH),
        ctime: meta.modified().unwrap_or(UNIX_EPOCH),
        crtime: meta.created().unwrap_or(UNIX_EPOCH),
        kind,
        perm: (meta.mode() & 0o7777) as u16,
        nlink: meta.nlink() as u32,
        uid: meta.uid(),
        gid: meta.gid(),
        rdev: meta.rdev() as u32,
        blksize: meta.blksize() as u32,
        flags: 0,
    }
}

fn filetime_from(t: TimeOrNow) -> FileTime {
    match t {
        TimeOrNow::SpecificTime(st) => FileTime::from_system_time(st),
        TimeOrNow::Now => FileTime::now(),
    }
}

/// std has no chown(); -1 (all bits set, per chown(2)) leaves an id
/// unchanged, which is how "only uid" or "only gid" is expressed here.
fn chown_path(path: &std::path::Path, uid: Option<u32>, gid: Option<u32>) -> std::io::Result<()> {
    let c_path = CString::new(path.as_os_str().as_bytes())?;
    let uid = uid.map(|u| u as libc::uid_t).unwrap_or(-1i32 as libc::uid_t);
    let gid = gid.map(|g| g as libc::gid_t).unwrap_or(-1i32 as libc::gid_t);
    let ret = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

impl<P: Prompter + Send + Sync + 'static, R: ProcessResolver + Send + Sync + 'static> Filesystem
    for PassthroughFs<P, R>
{
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let target = parent_path.join(name);
        if is_protected(&target) {
            reply.error(Errno::ENOENT);
            return;
        }
        match fs::symlink_metadata(&target) {
            Ok(meta) => {
                let ino = self.inodes.lock().unwrap().ino_for(target);
                reply.entry(&TTL, &attr_from_metadata(ino, &meta), Generation(0));
            }
            Err(_) => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let Some(path) = self.path_of(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match fs::symlink_metadata(&path) {
            Ok(meta) => reply.attr(&TTL, &attr_from_metadata(ino, &meta)),
            Err(_) => reply.error(Errno::ENOENT),
        }
    }

    // Read-only, like `getattr`/`readdir`: resolving a symlink reveals only
    // its target string, so it's not gated. Without it the kernel returns
    // ENOSYS for every `readlink`/`realpath` on a symlink in the vault, and
    // anything walking a path that passes through one (a recursive copy
    // re-creating links, `git`, an editor's canonicalize step) fails.
    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let Some(path) = self.path_of(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if is_protected(&path) {
            reply.error(Errno::ENOENT);
            return;
        }
        match fs::read_link(&path) {
            Ok(target) => reply.data(target.as_os_str().as_bytes()),
            Err(e) => reply.error(e.into()),
        }
    }

    // Handles truncate (size), chmod (mode), chown (uid/gid) and utimens
    // (atime/mtime) - anything else (macOS-only crtime/chgtime/bkuptime/
    // flags) is ignored, matching the default no-op on Linux. Gated the
    // same as open/create: without this, `truncate(path, n)` or
    // `utimensat` on a file the caller never `open()`'d would bypass the
    // authorization prompt entirely.
    fn setattr(
        &self,
        req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let Some(path) = self.path_of(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if is_protected(&path) || !self.authorize(req, &path) {
            reply.error(Errno::EACCES);
            return;
        }

        if let Some(size) = size {
            let result = OpenOptions::new()
                .write(true)
                .open(&path)
                .and_then(|f| f.set_len(size));
            if let Err(e) = result {
                reply.error(e.into());
                return;
            }
        }

        if let Some(mode) = mode {
            if let Err(e) = fs::set_permissions(&path, fs::Permissions::from_mode(mode)) {
                reply.error(e.into());
                return;
            }
        }

        if uid.is_some() || gid.is_some() {
            if let Err(e) = chown_path(&path, uid, gid) {
                reply.error(e.into());
                return;
            }
        }

        if atime.is_some() || mtime.is_some() {
            let meta = match fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) => {
                    reply.error(e.into());
                    return;
                }
            };
            let new_atime = atime
                .map(filetime_from)
                .unwrap_or_else(|| FileTime::from_last_access_time(&meta));
            let new_mtime = mtime
                .map(filetime_from)
                .unwrap_or_else(|| FileTime::from_last_modification_time(&meta));
            if let Err(e) = filetime::set_file_times(&path, new_atime, new_mtime) {
                reply.error(e.into());
                return;
            }
        }

        match fs::symlink_metadata(&path) {
            Ok(meta) => reply.attr(&TTL, &attr_from_metadata(ino, &meta)),
            Err(e) => reply.error(e.into()),
        }
    }

    // Report the backing filesystem's real free-space numbers. `fuser`'s
    // default `statfs` replies with zero blocks total and zero free, which
    // makes every space-aware caller believe the vault is full: KDE's KIO
    // copy job sums the source size and checks it against the destination's
    // free space *before* writing anything, so dragging a folder into the
    // vault in Dolphin fails outright with "not enough space" while a
    // plain `cp` (which never asks) works fine.
    fn statfs(&self, _req: &Request, ino: INodeNo, reply: ReplyStatfs) {
        let path = self
            .path_of(ino)
            .or_else(|| self.path_of(INodeNo::ROOT))
            .unwrap_or_else(|| PathBuf::from("/"));
        let c_path = match CString::new(path.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(Errno::EINVAL);
                return;
            }
        };
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c_path.as_ptr(), &mut st) } != 0 {
            reply.error(std::io::Error::last_os_error().into());
            return;
        }
        reply.statfs(
            st.f_blocks as u64,
            st.f_bfree as u64,
            st.f_bavail as u64,
            st.f_files as u64,
            st.f_ffree as u64,
            st.f_bsize as u32,
            st.f_namemax as u32,
            st.f_frsize as u32,
        );
    }

    fn opendir(&self, _req: &Request, _ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        reply.opened(FileHandle(0), FopenFlags::empty());
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let Some(path) = self.path_of(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let read_dir = match fs::read_dir(&path) {
            Ok(rd) => rd,
            Err(e) => {
                reply.error(e.into());
                return;
            }
        };

        let mut entries: Vec<(INodeNo, FileType, std::ffi::OsString)> = vec![
            (ino, FileType::Directory, ".".into()),
            (ino, FileType::Directory, "..".into()),
        ];
        for entry in read_dir.flatten() {
            if entry.file_name() == OsStr::new(WHITELIST_FILENAME) {
                continue;
            }
            let file_type = match entry.file_type() {
                Ok(ft) if ft.is_dir() => FileType::Directory,
                Ok(ft) if ft.is_symlink() => FileType::Symlink,
                _ => FileType::RegularFile,
            };
            let child_ino = self.inodes.lock().unwrap().ino_for(entry.path());
            entries.push((child_ino, file_type, entry.file_name()));
        }

        for (i, (entry_ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize)
        {
            if reply.add(entry_ino, (i + 1) as u64, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn open(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let Some(path) = self.path_of(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if is_protected(&path) || !self.authorize(req, &path) {
            reply.error(Errno::EACCES);
            return;
        }
        let mut opts = OpenOptions::new();
        match flags.acc_mode() {
            OpenAccMode::O_RDONLY => {
                opts.read(true);
            }
            OpenAccMode::O_WRONLY => {
                opts.write(true);
            }
            OpenAccMode::O_RDWR => {
                opts.read(true).write(true);
            }
        }
        match opts.open(&path) {
            Ok(file) => {
                let fh = self.alloc_fh();
                self.handles.lock().unwrap().insert(fh, Arc::new(file));
                self.mark_activity();
                reply.opened(FileHandle(fh), FopenFlags::empty());
            }
            Err(e) => reply.error(e.into()),
        }
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let target = parent_path.join(name);
        if is_protected(&target) || !self.authorize(req, &target) {
            reply.error(Errno::EACCES);
            return;
        }
        let opened = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&target);
        match opened {
            Ok(file) => match file.metadata() {
                Ok(meta) => {
                    let ino = self.inodes.lock().unwrap().ino_for(target);
                    let attr = attr_from_metadata(ino, &meta);
                    let fh = self.alloc_fh();
                    self.handles.lock().unwrap().insert(fh, Arc::new(file));
                    self.mark_activity();
                    reply.created(&TTL, &attr, Generation(0), FileHandle(fh), FopenFlags::empty());
                }
                Err(e) => reply.error(e.into()),
            },
            Err(e) => reply.error(e.into()),
        }
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let file = {
            let handles = self.handles.lock().unwrap();
            match handles.get(&fh.0) {
                Some(f) => Arc::clone(f),
                None => {
                    reply.error(Errno::EBADF);
                    return;
                }
            }
        };
        let mut buf = vec![0u8; size as usize];
        match file.read_at(&mut buf, offset) {
            Ok(n) => {
                self.mark_activity();
                buf.truncate(n);
                reply.data(&buf);
            }
            Err(e) => reply.error(e.into()),
        }
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let file = {
            let handles = self.handles.lock().unwrap();
            match handles.get(&fh.0) {
                Some(f) => Arc::clone(f),
                None => {
                    reply.error(Errno::EBADF);
                    return;
                }
            }
        };
        match file.write_at(data, offset) {
            Ok(n) => {
                self.mark_activity();
                reply.written(n as u32);
            }
            Err(e) => reply.error(e.into()),
        }
    }

    fn flush(&self, _req: &Request, _ino: INodeNo, _fh: FileHandle, _lock_owner: LockOwner, reply: ReplyEmpty) {
        reply.ok();
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.handles.lock().unwrap().remove(&fh.0);
        reply.ok();
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let target = parent_path.join(name);
        if is_protected(&target) || !self.authorize(req, &target) {
            reply.error(Errno::EACCES);
            return;
        }
        match fs::create_dir(&target) {
            Ok(()) => match fs::symlink_metadata(&target) {
                Ok(meta) => {
                    let ino = self.inodes.lock().unwrap().ino_for(target);
                    reply.entry(&TTL, &attr_from_metadata(ino, &meta), Generation(0));
                }
                Err(e) => reply.error(e.into()),
            },
            Err(e) => reply.error(e.into()),
        }
    }

    // Gated on the new link's path, like `create`/`mkdir`: the link itself
    // is a new name appearing in the vault. `link_target` is stored
    // verbatim (it may be relative, absolute, or dangling - the kernel
    // resolves it later, and any `open` of it comes back through this gate).
    fn symlink(
        &self,
        req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        link_target: &std::path::Path,
        reply: ReplyEntry,
    ) {
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let link_path = parent_path.join(link_name);
        if is_protected(&link_path) || !self.authorize(req, &link_path) {
            reply.error(Errno::EACCES);
            return;
        }
        match std::os::unix::fs::symlink(link_target, &link_path) {
            Ok(()) => match fs::symlink_metadata(&link_path) {
                Ok(meta) => {
                    let ino = self.inodes.lock().unwrap().ino_for(link_path);
                    reply.entry(&TTL, &attr_from_metadata(ino, &meta), Generation(0));
                }
                Err(e) => reply.error(e.into()),
            },
            Err(e) => reply.error(e.into()),
        }
    }

    // Hard link: a second name for an existing inode. Gated on the source
    // path (the content being aliased), matching how `rename` authorizes on
    // its source.
    fn link(
        &self,
        req: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let (Some(src), Some(new_parent)) = (self.path_of(ino), self.path_of(newparent)) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let link_path = new_parent.join(newname);
        if is_protected(&src) || is_protected(&link_path) || !self.authorize(req, &src) {
            reply.error(Errno::EACCES);
            return;
        }
        match fs::hard_link(&src, &link_path) {
            Ok(()) => match fs::symlink_metadata(&link_path) {
                Ok(meta) => {
                    let new_ino = self.inodes.lock().unwrap().ino_for(link_path);
                    reply.entry(&TTL, &attr_from_metadata(new_ino, &meta), Generation(0));
                }
                Err(e) => reply.error(e.into()),
            },
            Err(e) => reply.error(e.into()),
        }
    }

    fn unlink(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let target = parent_path.join(name);
        if is_protected(&target) || !self.authorize(req, &target) {
            reply.error(Errno::EACCES);
            return;
        }
        match fs::remove_file(&target) {
            Ok(()) => {
                self.inodes.lock().unwrap().forget_path(&target);
                reply.ok();
            }
            Err(e) => reply.error(e.into()),
        }
    }

    fn rmdir(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let target = parent_path.join(name);
        if is_protected(&target) || !self.authorize(req, &target) {
            reply.error(Errno::EACCES);
            return;
        }
        match fs::remove_dir(&target) {
            Ok(()) => {
                self.inodes.lock().unwrap().forget_path(&target);
                reply.ok();
            }
            Err(e) => reply.error(e.into()),
        }
    }

    fn rename(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        _flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let (Some(old_parent), Some(new_parent)) = (self.path_of(parent), self.path_of(newparent))
        else {
            reply.error(Errno::ENOENT);
            return;
        };
        let old = old_parent.join(name);
        let new = new_parent.join(newname);
        if is_protected(&old) || is_protected(&new) || !self.authorize(req, &old) {
            reply.error(Errno::EACCES);
            return;
        }
        match fs::rename(&old, &new) {
            Ok(()) => {
                self.inodes.lock().unwrap().rename(&old, new);
                reply.ok();
            }
            Err(e) => reply.error(e.into()),
        }
    }
}
