use whenfs::time_expr;

use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    ReplyOpen, ReplyWrite, Request,
};
use libc::{EACCES, ENOENT, EROFS};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration as StdDuration, SystemTime};

const ROOT_INO: u64 = 1;
const TTL: StdDuration = StdDuration::from_secs(60);

struct WhenFs {
    snap_root: PathBuf,
    next_ino: AtomicU64,
    path_of: Mutex<HashMap<u64, PathBuf>>,
    ino_of: Mutex<HashMap<PathBuf, u64>>,
    handles: Mutex<HashMap<u64, File>>,
    next_fh: AtomicU64,
}

impl WhenFs {
    fn new(snap_root: PathBuf) -> Self {
        WhenFs {
            snap_root,
            next_ino: AtomicU64::new(2),
            path_of: Mutex::new(HashMap::new()),
            ino_of: Mutex::new(HashMap::new()),
            handles: Mutex::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
        }
    }

    fn ino_for_path(&self, path: &Path) -> u64 {
        let canon = path.to_path_buf();
        let mut ino_of = self.ino_of.lock().unwrap();
        if let Some(&ino) = ino_of.get(&canon) {
            return ino;
        }
        let ino = self.next_ino.fetch_add(1, Ordering::SeqCst);
        ino_of.insert(canon.clone(), ino);
        self.path_of.lock().unwrap().insert(ino, canon);
        ino
    }

    fn path_for_ino(&self, ino: u64) -> Option<PathBuf> {
        self.path_of.lock().unwrap().get(&ino).cloned()
    }

    fn attr_for(&self, ino: u64, meta: &fs::Metadata) -> FileAttr {
        let kind = if meta.is_dir() {
            FileType::Directory
        } else if meta.is_symlink() {
            FileType::Symlink
        } else {
            FileType::RegularFile
        };
        let perm = (meta.mode() & 0o555) as u16; // strip write bits, read-only mount
        FileAttr {
            ino,
            size: meta.size(),
            blocks: meta.blocks(),
            atime: meta.accessed().unwrap_or(SystemTime::UNIX_EPOCH),
            mtime: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            ctime: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            crtime: SystemTime::UNIX_EPOCH,
            kind,
            perm,
            nlink: meta.nlink() as u32,
            uid: meta.uid(),
            gid: meta.gid(),
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }
}

impl Filesystem for WhenFs {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name = match name.to_str() {
            Some(n) => n,
            None => return reply.error(ENOENT),
        };

        let target_path = if parent == ROOT_INO {
            match time_expr::resolve(&self.snap_root, name) {
                Some(p) => p,
                None => return reply.error(ENOENT),
            }
        } else {
            let parent_path = match self.path_for_ino(parent) {
                Some(p) => p,
                None => return reply.error(ENOENT),
            };
            parent_path.join(name)
        };

        match fs::symlink_metadata(&target_path) {
            Ok(meta) => {
                let ino = self.ino_for_path(&target_path);
                reply.entry(&TTL, &self.attr_for(ino, &meta), 0);
            }
            Err(_) => reply.error(ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        if ino == ROOT_INO {
            let now = SystemTime::now();
            let attr = FileAttr {
                ino: ROOT_INO,
                size: 0,
                blocks: 0,
                atime: now,
                mtime: now,
                ctime: now,
                crtime: now,
                kind: FileType::Directory,
                perm: 0o555,
                nlink: 2,
                uid: unsafe { libc::getuid() },
                gid: unsafe { libc::getgid() },
                rdev: 0,
                blksize: 4096,
                flags: 0,
            };
            return reply.attr(&TTL, &attr);
        }

        let path = match self.path_for_ino(ino) {
            Some(p) => p,
            None => return reply.error(ENOENT),
        };
        match fs::symlink_metadata(&path) {
            Ok(meta) => reply.attr(&TTL, &self.attr_for(ino, &meta)),
            Err(_) => reply.error(ENOENT),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let mut entries: Vec<(u64, FileType, String)> = vec![
            (ino, FileType::Directory, ".".into()),
            (ino, FileType::Directory, "..".into()),
        ];

        if ino == ROOT_INO {
            for shortcut in ["now", "today", "yesterday", "last-week", "last-month"] {
                if let Some(target) = time_expr::resolve(&self.snap_root, shortcut) {
                    let _ = target;
                    entries.push((
                        self.ino_for_path(&self.snap_root),
                        FileType::Directory,
                        shortcut.into(),
                    ));
                }
            }
        } else {
            let path = match self.path_for_ino(ino) {
                Some(p) => p,
                None => return reply.error(ENOENT),
            };
            if let Ok(rd) = fs::read_dir(&path) {
                for entry in rd.flatten() {
                    let child_path = entry.path();
                    let file_type = match entry.file_type() {
                        Ok(ft) if ft.is_dir() => FileType::Directory,
                        Ok(ft) if ft.is_symlink() => FileType::Symlink,
                        _ => FileType::RegularFile,
                    };
                    let child_ino = self.ino_for_path(&child_path);
                    let name = entry.file_name().to_string_lossy().into_owned();
                    entries.push((child_ino, file_type, name));
                }
            }
        }

        for (i, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(ino, (i + 1) as i64, kind, &name) {
                break;
            }
        }
        reply.ok();
    }

    fn opendir(&mut self, _req: &Request, _ino: u64, _flags: i32, reply: fuser::ReplyOpen) {
        reply.opened(0, 0);
    }

    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        let write_requested =
            flags & (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC) != 0;
        if write_requested {
            return reply.error(EROFS);
        }
        let path = match self.path_for_ino(ino) {
            Some(p) => p,
            None => return reply.error(ENOENT),
        };
        match File::open(&path) {
            Ok(f) => {
                let fh = self.next_fh.fetch_add(1, Ordering::SeqCst);
                self.handles.lock().unwrap().insert(fh, f);
                reply.opened(fh, 0);
            }
            Err(_) => reply.error(EACCES),
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let mut handles = self.handles.lock().unwrap();
        let file = match handles.get_mut(&fh) {
            Some(f) => f,
            None => return reply.error(ENOENT),
        };
        let mut buf = vec![0u8; size as usize];
        if file.seek(SeekFrom::Start(offset as u64)).is_err() {
            return reply.error(EACCES);
        }
        match file.read(&mut buf) {
            Ok(n) => reply.data(&buf[..n]),
            Err(_) => reply.error(EACCES),
        }
    }

    fn release(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        self.handles.lock().unwrap().remove(&fh);
        reply.ok();
    }

    // --- read-only enforcement: reject every mutating op explicitly ---

    fn write(
        &mut self,
        _req: &Request,
        _ino: u64,
        _fh: u64,
        _offset: i64,
        _data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        reply.error(EROFS);
    }

    fn setattr(
        &mut self,
        _req: &Request,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        _size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        // no-op success would lie about mutability; report the real attrs, changes rejected upstream in open/write
        if let Some(path) = self.path_for_ino(ino)
            && let Ok(meta) = fs::symlink_metadata(&path)
        {
            return reply.attr(&TTL, &self.attr_for(ino, &meta));
        }
        reply.error(ENOENT);
    }

    fn mkdir(
        &mut self,
        _req: &Request,
        _parent: u64,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        reply.error(EROFS);
    }

    fn create(
        &mut self,
        _req: &Request,
        _parent: u64,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        reply.error(EROFS);
    }

    fn unlink(&mut self, _req: &Request, _parent: u64, _name: &OsStr, reply: fuser::ReplyEmpty) {
        reply.error(EROFS);
    }

    fn rmdir(&mut self, _req: &Request, _parent: u64, _name: &OsStr, reply: fuser::ReplyEmpty) {
        reply.error(EROFS);
    }

    fn rename(
        &mut self,
        _req: &Request,
        _parent: u64,
        _name: &OsStr,
        _newparent: u64,
        _newname: &OsStr,
        _flags: u32,
        reply: fuser::ReplyEmpty,
    ) {
        reply.error(EROFS);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: whenfs <snap-root> <mountpoint>");
        std::process::exit(1);
    }
    let snap_root = PathBuf::from(&args[1]);
    let mountpoint = &args[2];

    let fs = WhenFs::new(snap_root);
    let options = vec![MountOption::RO, MountOption::FSName("whenfs".to_string())];
    fuser::mount2(fs, mountpoint, &options).unwrap();
}
