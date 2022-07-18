// TODO: Implement the root VFS trait
// TODO: Implement a trait representing a file/resource handle.

// A lot o&f the work here is being cribbed from https://github.com/rkusa/sqlite-vfs/blob/main/src/lib.rs

use libsqlite3_sys as ffi;
use std::{
    borrow::Cow,
    ffi::CString,
    os::raw,
    ptr,
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::Error;

static RUSQLITE_VFS_VERSION_IO_METHODS: i32 = 3;
static RUSQLITE_VFS_VERSION_IMPL: i32 = 3;

macro_rules! from_cstr {
    ($state: expr, $cstr: expr, $msg: expr) => {
        match CStr::from_ptr($cstr).to_str() {
            Ok(cstr_value) => cstr_value,
            Err(err) => {
                return $state.set_last_error(
                    ffi::SQLITE_ERROR,
                    std::io::Error::new(
                        ErrorKind::Other,
                        format!(
                            "{} (received: {:?}) because of {:#?}",
                            $msg,
                            CStr::from_ptr($cstr),
                            err
                        ),
                    ),
                )
            }
        }
    };
}

/// Options for opening a file.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenOptions {
    /// The object type that is being opened.
    pub kind: OpenKind,

    /// The access an object is opened with.
    pub access: OpenAccess,

    /// Determines if this file will be deleted on close.
    pub delete_on_close: bool,
}

impl OpenKind {
    fn from_flags(flags: i32) -> Option<Self> {
        match flags {
            flags if flags & ffi::SQLITE_OPEN_MAIN_DB > 0 => Some(Self::MainDb),
            flags if flags & ffi::SQLITE_OPEN_MAIN_JOURNAL > 0 => Some(Self::MainJournal),
            flags if flags & ffi::SQLITE_OPEN_TEMP_DB > 0 => Some(Self::TempDb),
            flags if flags & ffi::SQLITE_OPEN_TEMP_JOURNAL > 0 => Some(Self::TempJournal),
            flags if flags & ffi::SQLITE_OPEN_TRANSIENT_DB > 0 => Some(Self::TransientDb),
            flags if flags & ffi::SQLITE_OPEN_SUBJOURNAL > 0 => Some(Self::SubJournal),
            flags if flags & ffi::SQLITE_OPEN_SUPER_JOURNAL > 0 => Some(Self::SuperJournal),
            flags if flags & ffi::SQLITE_OPEN_WAL > 0 => Some(Self::Wal),
            _ => None,
        }
    }

    fn to_flags(self) -> i32 {
        match self {
            OpenKind::MainDb => ffi::SQLITE_OPEN_MAIN_DB,
            OpenKind::MainJournal => ffi::SQLITE_OPEN_MAIN_JOURNAL,
            OpenKind::TempDb => ffi::SQLITE_OPEN_TEMP_DB,
            OpenKind::TempJournal => ffi::SQLITE_OPEN_TEMP_JOURNAL,
            OpenKind::TransientDb => ffi::SQLITE_OPEN_TRANSIENT_DB,
            OpenKind::SubJournal => ffi::SQLITE_OPEN_SUBJOURNAL,
            OpenKind::SuperJournal => ffi::SQLITE_OPEN_SUPER_JOURNAL,
            OpenKind::Wal => ffi::SQLITE_OPEN_WAL,
        }
    }
}

impl OpenAccess {
    fn from_flags(flags: i32) -> Option<Self> {
        match flags {
            flags
                if (flags & ffi::SQLITE_OPEN_CREATE > 0)
                    && (flags & ffi::SQLITE_OPEN_EXCLUSIVE > 0) =>
            {
                Some(Self::CreateNew)
            }
            flags if flags & ffi::SQLITE_OPEN_CREATE > 0 => Some(Self::Create),
            flags if flags & ffi::SQLITE_OPEN_READWRITE > 0 => Some(Self::Write),
            flags if flags & ffi::SQLITE_OPEN_READONLY > 0 => Some(Self::Read),
            _ => None,
        }
    }

    fn to_flags(self) -> i32 {
        match self {
            OpenAccess::Read => ffi::SQLITE_OPEN_READONLY,
            OpenAccess::Write => ffi::SQLITE_OPEN_READWRITE,
            OpenAccess::Create => ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE,
            OpenAccess::CreateNew => {
                ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE | ffi::SQLITE_OPEN_EXCLUSIVE
            }
        }
    }

    /// Determines if there's a hint to create this file first.
    pub fn should_create(&self) -> bool {
        matches!(self, Self::Create) || matches!(self, Self::CreateNew)
    }
}

impl OpenOptions {
    fn from_flags(flags: i32) -> Option<Self> {
        Some(OpenOptions {
            kind: OpenKind::from_flags(flags)?,
            access: OpenAccess::from_flags(flags)?,
            delete_on_close: flags & ffi::SQLITE_OPEN_DELETEONCLOSE > 0,
        })
    }

    fn to_flags(&self) -> i32 {
        self.kind.to_flags()
            | self.access.to_flags()
            | if self.delete_on_close {
                ffi::SQLITE_OPEN_DELETEONCLOSE
            } else {
                0
            }
    }
}

/// The access an object is opened with.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OpenAccess {
    /// Read access.
    Read,

    /// Write access (includes read access).
    Write,

    /// Create the file if it does not exist (includes write and read access).
    Create,

    /// Create the file, but throw if it it already exist (includes write and read access).
    CreateNew,
}

impl Into<std::fs::OpenOptions> for OpenAccess {
    fn into(self) -> std::fs::OpenOptions {
        let mut o = std::fs::OpenOptions::new();
        o.read(true).write(self != Self::Read);
        match self {
            Self::Create => {
                o = o.create(true).clone();
            }
            Self::CreateNew => {
                o = o.create_new(true).clone();
            }
            _ => {}
        };

        o
    }
}

/// The object type that is being opened.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OpenKind {
    /// Main database
    MainDb,
    /// Main journal.
    MainJournal,
    /// Temp database
    TempDb,
    /// Temp journal.
    TempJournal,
    /// Transient db.
    TransientDb,
    /// Sub journal.
    SubJournal,
    /// Super journal.
    SuperJournal,
    /// Write-ahead log.
    Wal,
}

/// A file on the filesystem.
#[repr(C)]
pub struct File<F: Filesystem> {
    base: ffi::sqlite3_file,
    filesystem: Arc<State<F>>,
    resource: Option<Box<F::Handle>>,
    database_name: String,
    state: State<F>,
    wal_persistence: bool,
    powersafe_overwrite: bool,
}

fn no_file_err(path: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!(
            "No file has been associated to this resource claiming {:?}",
            path
        ),
    )
}

impl<F: Filesystem> File<F> {
    /// Reads some bytes into a buffer.
    pub fn read_bytes(&mut self, mut buffer: &mut [u8], offset: usize) -> std::io::Result<()> {
        if let Some(r) = self.resource.as_mut() {
            r.read_bytes(&mut buffer, offset)
        } else {
            Err(no_file_err(&self.database_name))
        }
    }

    /// Writes n bytes into a buffer.
    pub fn write_bytes(&mut self, buffer: &[u8], offset: usize) -> std::io::Result<()> {
        if let Some(r) = self.resource.as_mut() {
            r.write_bytes(buffer, offset)
        } else {
            Err(no_file_err(&self.database_name))
        }
    }

    /// Obtains the size of the file.
    pub fn file_size(&self) -> std::io::Result<usize> {
        if let Some(r) = &self.resource {
            r.file_size()
        } else {
            Err(no_file_err(&self.database_name))
        }
    }

    /// Gets the sector size of a file.
    pub fn sector_size(&self) -> usize {
        F::sector_size()
    }
}

/// Represents a file handle on a filesystem.
pub trait Resource: Sync + Clone {
    /// Read bytes.
    fn read_bytes(&mut self, buffer: &mut [u8], offset: usize) -> std::io::Result<()>;

    /// Write bytes.
    fn write_bytes(&mut self, buffer: &[u8], offset: usize) -> std::io::Result<()>;

    /// File size.
    fn file_size(&self) -> std::io::Result<usize>;

    /// Has moved?
    fn has_moved(&self) -> std::io::Result<bool>;

    /// The lock state.
    fn lock_state(&self) -> std::io::Result<LockState>;

    /// Set the lock state.
    fn set_lock_state(&mut self, new_lock_state: LockState) -> std::io::Result<()>;

    /// Close out the file.
    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    /// Synchronize file information to the system.
    ///
    /// This can be safely ignored by implementations that don't need it.
    fn sync(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    /// Adjust the hint representing the size of the file.
    ///
    /// This can be safely ignored by implementations that don't need it.
    /// This _should_ be considered a value that can be multipled against
    /// one's chunk size.
    fn apply_size_hint(&mut self, _size_hint: usize) -> std::io::Result<()> {
        Ok(())
    }

    /// Returns the size of chunks the databae is stored in.
    fn chunk_size(&self) -> std::io::Result<usize> {
        Ok(1024)
    }

    /// Adjust the chunk size.
    fn apply_chunk_size(&mut self, _chunk_size: usize) -> std::io::Result<()> {
        Ok(())
    }
}

/// The kind of access to check for.
pub enum FileAccess {
    /// Only can read?
    Readonly,
    /// Only can write?
    Writable,
    /// Can read and write
    ReadWrite,
}

/// The filesystem.
pub trait Filesystem: Sync + Send {
    /// A representation of a file handle on this system.
    type Handle: Resource;

    /// Obtains the full path of a provided string.
    fn full_pathname<'a>(&self, pathname: &'a str) -> std::io::Result<Cow<'a, str>>;

    /// Obtains the maximum length of a path.
    fn maximum_file_pathname_size() -> usize {
        1024
    }

    /// The size of a sector
    fn sector_size() -> usize {
        1
    }

    /// Check access to `db`.
    fn exists(&self, path: &str) -> std::io::Result<bool>;

    /// Check access to `db`.
    fn access(&self, path: &str, level: FileAccess) -> std::io::Result<bool>;

    /// Generates random bytes.
    fn random_bytes(&self, buffer: &mut [i8]);

    /// Sleeps for the time specified.
    fn sleep(&self, duration: Duration) -> Duration;

    /// Opens a file.
    fn open(&self, path: String, flags: OpenOptions) -> std::io::Result<Self::Handle>;

    /// Deletes the file.
    fn delete(&self, path: String) -> std::io::Result<()>;

    /// Generates a temporary filename.
    fn temporary_filename(&self) -> std::io::Result<String>;
}

/// The access an object is opened with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// No locks are held. The database may be neither read nor written. Any internally cached data
    /// is considered suspect and subject to verification against the database file before being
    /// used. Other processes can read or write the database as their own locking states permit.
    /// This is the default state.
    None,

    /// The database may be read but not written. Any number of processes can hold
    /// [LockKind::Shared] locks at the same time, hence there can be many simultaneous readers. But
    /// no other thread or process is allowed to write to the database file while one or more
    /// [LockKind::Shared] locks are active.
    Shared,

    /// A [LockKind::Reserved] lock means that the process is planning on writing to the database
    /// file at some point in the future but that it is currently just reading from the file. Only a
    /// single [LockKind::Reserved] lock may be active at one time, though multiple
    /// [LockKind::Shared] locks can coexist with a single [LockKind::Reserved] lock.
    /// [LockKind::Reserved] differs from [LockKind::Pending] in that new [LockKind::Shared] locks
    /// can be acquired while there is a [LockKind::Reserved] lock.
    Reserved,

    /// A [LockKind::Pending] lock means that the process holding the lock wants to write to the
    /// database as soon as possible and is just waiting on all current [LockKind::Shared] locks to
    /// clear so that it can get an [LockKind::Exclusive] lock. No new [LockKind::Shared] locks are
    /// permitted against the database if a [LockKind::Pending] lock is active, though existing
    /// [LockKind::Shared] locks are allowed to continue.
    Pending,

    /// An [LockKind::Exclusive] lock is needed in order to write to the database file. Only one
    /// [LockKind::Exclusive] lock is allowed on the file and no other locks of any kind are allowed
    /// to coexist with an [LockKind::Exclusive] lock. In order to maximize concurrency, SQLite
    /// works to minimize the amount of time that [LockKind::Exclusive] locks are held.
    Exclusive,
}

impl From<i32> for LockState {
    fn from(lock: i32) -> Self {
        match lock {
            ffi::SQLITE_LOCK_NONE => Self::None,
            ffi::SQLITE_LOCK_SHARED => Self::Shared,
            ffi::SQLITE_LOCK_RESERVED => Self::Reserved,
            ffi::SQLITE_LOCK_PENDING => Self::Pending,
            ffi::SQLITE_LOCK_EXCLUSIVE => Self::Exclusive,
            _ => Self::None,
        }
    }
}

impl Into<i32> for LockState {
    fn into(self) -> i32 {
        match self {
            Self::None => ffi::SQLITE_LOCK_NONE,
            Self::Shared => ffi::SQLITE_LOCK_SHARED,
            Self::Reserved => ffi::SQLITE_LOCK_RESERVED,
            Self::Pending => ffi::SQLITE_LOCK_PENDING,
            Self::Exclusive => ffi::SQLITE_LOCK_EXCLUSIVE,
        }
    }
}

impl PartialOrd for LockState {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let selfi: i32 = (*self).into();
        let otheri = (*other).into();
        selfi.partial_cmp(&otheri)
    }
}

impl Default for LockState {
    fn default() -> Self {
        Self::None
    }
}

impl LockState {
    /// Determines if this is locked.
    pub fn is_locked(&self) -> bool {
        *self != Self::None
    }
}

unsafe fn underlying_state<'a, F: Filesystem>(
    ptr: *mut ffi::sqlite3_vfs,
) -> Option<&'a mut State<F>> {
    let vfs: &mut ffi::sqlite3_vfs = ptr.as_mut()?;
    (vfs.pAppData as *mut State<F>).as_mut()
}

unsafe fn underlying_resource<'a, F: Filesystem>(
    ptr: *mut ffi::sqlite3_file,
) -> Option<&'a mut File<F>> {
    let file: *mut ffi::sqlite3_file = ptr.as_mut()?;
    (file as *mut File<F>).as_mut()
}

fn null_ptr_error() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, "received null pointer")
}

mod node {
    use std::{borrow::Borrow, ffi::CStr, io::ErrorKind, mem::ManuallyDrop};

    use super::*;

    macro_rules! get_state {
        ($f: expr) => {
            match underlying_resource::<F>($f) {
                Some(s) => s,
                None => return ffi::SQLITE_IOERR_FSYNC,
            }
        };
    }

    macro_rules! get_resource_from_state {
        ($f: expr, $err_code: expr, $path: expr) => {
            match $f.resource.as_mut() {
                Some(r) => r,
                None => return $f.state.set_last_error($err_code, no_file_err($path)),
            }
        };
    }

    pub unsafe extern "C" fn close<F: Filesystem>(p_file: *mut ffi::sqlite3_file) -> raw::c_int {
        let state = get_state!(p_file);

        println!("[vfs::close] Closing {:?}", state.database_name);
        let r = get_resource_from_state!(state, ffi::SQLITE_IOERR_CLOSE, &state.database_name);

        if let Err(e) = r.close() {
            state.state.set_last_error(ffi::SQLITE_IOERR_CLOSE, e)
        } else {
            drop(state);
            ffi::SQLITE_OK
        }
    }

    pub unsafe extern "C" fn read<F: Filesystem>(
        p_file: *mut ffi::sqlite3_file,
        z_buf: *mut raw::c_void,
        i_amt: raw::c_int,
        i_ofst: ffi::sqlite3_int64,
    ) -> raw::c_int {
        let state = get_state!(p_file);

        println!(
            "[vfs::read] Reading at an offset of {} bytes seeking {} bytes from {:?}",
            i_ofst, i_amt, state.database_name
        );

        let out = std::slice::from_raw_parts_mut(z_buf as *mut u8, i_amt as usize);
        if let Err(err) = state.read_bytes(out, i_ofst as usize) {
            println!(
                "[vfs::read] Read of {} bytes was unsuccessful: {:#?}.",
                i_amt, err
            );
            let kind = err.kind();
            if kind == ErrorKind::UnexpectedEof {
                println!("[vfs::read] short read err");
                ffi::SQLITE_IOERR_SHORT_READ
            } else {
                println!("[vfs::read] failed {:#?}", err);
                return state.state.set_last_error(ffi::SQLITE_IOERR_READ, err);
            }
        } else {
            println!("[vfs::read] Reporting back {} bytes", out.len());
            ffi::SQLITE_OK
        }
    }

    pub unsafe extern "C" fn write<F: Filesystem>(
        p_file: *mut ffi::sqlite3_file,
        z: *const raw::c_void,
        i_amt: raw::c_int,
        i_ofst: ffi::sqlite3_int64,
    ) -> raw::c_int {
        let state = get_state!(p_file);

        println!(
            "[vfs::write] Writing into {} at the offset of {} with {} bytes",
            state.database_name, i_ofst, i_amt
        );

        let data = std::slice::from_raw_parts(z as *mut u8, i_amt as usize);
        println!("[vfs::write] Claimed a buffer of {} bytes", data.len());

        let result = state.write_bytes(data, i_ofst as usize);

        println!("[vfs::write] Was the write successful? {:?}", result);

        match result {
            Ok(()) => ffi::SQLITE_OK,
            Err(err) if err.kind() == ErrorKind::WriteZero => ffi::SQLITE_FULL,
            Err(err) => state.state.set_last_error(ffi::SQLITE_IOERR_WRITE, err),
        }
    }

    pub unsafe extern "C" fn truncate<F: Filesystem>(
        p_file: *mut ffi::sqlite3_file,
        size: ffi::sqlite3_int64,
    ) -> raw::c_int {
        let state = get_state!(p_file);
        println!(
            "[vfs::truncate] Truncating {} bytes from {:?}",
            size, state.database_name
        );

        ffi::SQLITE_OK
    }

    pub unsafe extern "C" fn sync<F: Filesystem>(
        p_file: *mut ffi::sqlite3_file,
        _flags: raw::c_int,
    ) -> raw::c_int {
        let state = get_state!(p_file);
        println!(
            "[vfs::sync] Synchronizing the metadata for {:?}",
            state.database_name
        );

        ffi::SQLITE_OK
    }

    pub unsafe extern "C" fn file_size<F: Filesystem>(
        p_file: *mut ffi::sqlite3_file,
        p_size: *mut ffi::sqlite3_int64,
    ) -> raw::c_int {
        let state = get_state!(p_file);
        println!(
            "[vfs::file_size] Getting the file size of {:?}...",
            state.database_name
        );
        if let Err(err) = state.file_size().and_then(|n| {
            println!(
                "[vfs::file_size] Size of {:?} is reporting as {} bytes.",
                state.database_name, n
            );

            let p_size: &mut ffi::sqlite3_int64 = p_size.as_mut().ok_or_else(null_ptr_error)?;
            *p_size = n as ffi::sqlite3_int64;
            Ok(())
        }) {
            state.state.set_last_error(ffi::SQLITE_IOERR_FSTAT, err)
        } else {
            ffi::SQLITE_OK
        }
    }

    pub unsafe extern "C" fn lock<F: Filesystem>(
        p_file: *mut ffi::sqlite3_file,
        e_lock: raw::c_int,
    ) -> raw::c_int {
        let state = get_state!(p_file);
        let lock_kind = LockState::from(e_lock as i32);
        println!(
            "[vfs::lock] Requesting to set the lock to the {:?} lock",
            lock_kind
        );

        set_lock(state, lock_kind)
    }

    fn set_lock<F: Filesystem>(state: &mut File<F>, lock_state: LockState) -> raw::c_int {
        let r = get_resource_from_state!(state, ffi::SQLITE_ERROR, &state.database_name);
        if let Err(e) = r.set_lock_state(lock_state) {
            state.state.set_last_error(ffi::SQLITE_IOERR_FSTAT, e)
        } else {
            ffi::SQLITE_OK
        }
    }

    pub unsafe extern "C" fn unlock<F: Filesystem>(
        p_file: *mut ffi::sqlite3_file,
        e_lock: raw::c_int,
    ) -> raw::c_int {
        let state = get_state!(p_file);
        let lock_kind = LockState::from(e_lock as i32);
        println!(
            "[vfs::unlock] Requesting to lift the lock to a state of {:?}",
            lock_kind
        );

        set_lock(state, lock_kind)
    }

    pub unsafe extern "C" fn check_reserved_lock<F: Filesystem>(
        p_file: *mut ffi::sqlite3_file,
        p_res_out: *mut raw::c_int,
    ) -> raw::c_int {
        let state = get_state!(p_file);
        println!("[vfs::check_reserved_lock] Checking the status of the current lock.");

        if let Some(r) = &state.resource {
            if let Err(err) = r.lock_state().and_then(|lock| {
                let p_res_out: &mut raw::c_int = p_res_out.as_mut().ok_or_else(null_ptr_error)?;
                println!("[vfs::check_reserved_lock] We have a {:?} lock", lock);
                *p_res_out = lock.is_locked() as raw::c_int;
                Ok(())
            }) {
                return state.state.set_last_error(ffi::SQLITE_IOERR_UNLOCK, err);
            }

            ffi::SQLITE_OK
        } else {
            state
                .state
                .set_last_error(ffi::SQLITE_IOERR_FSTAT, no_file_err(&state.database_name))
        }
    }

    pub unsafe extern "C" fn file_control<F: Filesystem>(
        p_file: *mut ffi::sqlite3_file,
        op: raw::c_int,
        p_arg: *mut raw::c_void,
    ) -> raw::c_int {
        let state = get_state!(p_file);
        println!(
            "[vfs::file_size] Enacting file control on {:?} with the opcode {:?} ...",
            state.database_name, op
        );

        // Docs: https://www.sqlite.org/c3ref/c_fcntl_begin_atomic_write.html
        match op {
            // The following op codes are alreay handled by sqlite before, so no need to handle them
            // in a custom VFS.
            ffi::SQLITE_FCNTL_FILE_POINTER
            | ffi::SQLITE_FCNTL_VFS_POINTER
            | ffi::SQLITE_FCNTL_JOURNAL_POINTER
            | ffi::SQLITE_FCNTL_DATA_VERSION
            | ffi::SQLITE_FCNTL_RESERVE_BYTES => ffi::SQLITE_NOTFOUND,

            // The following op codes are no longer used and thus ignored.
            ffi::SQLITE_FCNTL_SYNC_OMITTED => ffi::SQLITE_NOTFOUND,

            // Used for debugging. Write current state of the lock into (int)pArg.
            ffi::SQLITE_FCNTL_LOCKSTATE => {
                // FIXME: Add logic for locking.
                // match state.current_lock() {
                // Ok(lock) => {
                //     if let Some(p_arg) = (p_arg as *mut i32).as_mut() {
                //         *p_arg = lock as i32;
                //     }
                //     ffi::SQLITE_OK
                // }
                // Err(err) => state.state.set_last_error(ffi::SQLITE_ERROR, err),

                // }
                ffi::SQLITE_NOTFOUND
            }

            // Relevant for proxy-type locking. Not implemented.
            ffi::SQLITE_FCNTL_GET_LOCKPROXYFILE | ffi::SQLITE_FCNTL_SET_LOCKPROXYFILE => {
                ffi::SQLITE_NOTFOUND
            }

            // Write last error number into (int)pArg.
            ffi::SQLITE_FCNTL_LAST_ERRNO => {
                // FIXME: Store error numbers like this on the file.
                if let Some(p_arg) = (p_arg as *mut i32).as_mut() {
                    if let Ok(code) = state
                        .state
                        .error
                        .lock()
                        .map(|g| g.as_ref().map(|(code, _)| code.clone()).unwrap_or_default())
                    {
                        *p_arg = code;
                    }
                }
                ffi::SQLITE_OK
            }

            // Give the VFS layer a hint of how large the database file will grow to be during the
            // current transaction.
            ffi::SQLITE_FCNTL_SIZE_HINT => {
                let r = get_resource_from_state!(state, ffi::SQLITE_ERROR, &state.database_name);
                let size_hint = match (p_arg as *mut i64).as_ref().cloned().map(|s| s.abs()) {
                    Some(hint) => hint,
                    None => {
                        return state.state.set_last_error(
                            ffi::SQLITE_NOTFOUND,
                            std::io::Error::new(ErrorKind::Other, "expect size hint arg"),
                        );
                    }
                };

                println!(
                    "[vfs::fcntrl] Adjusting the size hint to be {:?}",
                    size_hint
                );

                if let Err(e) = r.apply_size_hint(size_hint as usize) {
                    println!(
                        "[vfs::fcntrl] Failed to set the size hint for {:?} to be {}: {:#?}",
                        state.database_name, size_hint, e
                    );
                    return state.state.set_last_error(ffi::SQLITE_IOERR_TRUNCATE, e);
                }

                ffi::SQLITE_OK
            }

            // Request that the VFS extends and truncates the database file in chunks of a size
            // specified by the user. Return an error as this is not forwarded to the [Vfs] trait
            // right now.
            ffi::SQLITE_FCNTL_CHUNK_SIZE => {
                use std::convert::TryFrom;

                let chunk_size = match (p_arg as *mut i32)
                    .as_ref()
                    .cloned()
                    .and_then(|s| usize::try_from(s).ok())
                {
                    Some(chunk_size) => chunk_size,
                    None => {
                        return state.state.set_last_error(
                            ffi::SQLITE_NOTFOUND,
                            std::io::Error::new(ErrorKind::Other, "expect chunk_size arg"),
                        );
                    }
                };

                let r = get_resource_from_state!(state, ffi::SQLITE_ERROR, &state.database_name);

                println!(
                    "[vfs::fcntrl] Adjusting the chunk size to be {:?}",
                    chunk_size
                );

                if let Err(err) = r.apply_chunk_size(chunk_size) {
                    return state.state.set_last_error(ffi::SQLITE_ERROR, err);
                };

                ffi::SQLITE_OK
            }

            // Configure automatic retry counts and intervals for certain disk I/O operations for
            // the windows VFS in order to provide robustness in the presence of anti-virus
            // programs. Not implemented. But also, Windows?
            ffi::SQLITE_FCNTL_WIN32_AV_RETRY => ffi::SQLITE_NOTFOUND,

            // Enable or disable the persistent WAL setting.
            ffi::SQLITE_FCNTL_PERSIST_WAL => {
                if let Some(p_arg) = (p_arg as *mut i32).as_mut() {
                    if *p_arg < 0 {
                        // query current setting
                        *p_arg = state.wal_persistence as i32;
                    } else {
                        state.wal_persistence = *p_arg == 1;
                    }
                };

                ffi::SQLITE_OK
            }

            // Indicate that, unless it is rolled back for some reason, the entire database file
            // will be overwritten by the current transaction. Not implemented.
            ffi::SQLITE_FCNTL_OVERWRITE => {
                println!("[vfs::fcntrl] Pending truncation of whole file.");
                ffi::SQLITE_OK
            }

            // Used to obtain the names of all VFSes in the VFS stack.
            ffi::SQLITE_FCNTL_VFSNAME => {
                if let Some(p_arg) = (p_arg as *mut *const raw::c_char).as_mut() {
                    let name = ManuallyDrop::new(state.state.name.clone());
                    *p_arg = name.as_ptr();
                };

                ffi::SQLITE_OK
            }

            // Set or query the persistent "powersafe-overwrite" or "PSOW" setting.
            ffi::SQLITE_FCNTL_POWERSAFE_OVERWRITE => {
                if let Some(p_arg) = (p_arg as *mut i32).as_mut() {
                    if *p_arg < 0 {
                        // query current setting
                        *p_arg = state.powersafe_overwrite as i32;
                    } else {
                        state.powersafe_overwrite = *p_arg == 1;
                    }
                };

                ffi::SQLITE_OK
            }

            // Optionally intercept PRAGMA statements. Always fall back to normal pragma processing.
            ffi::SQLITE_FCNTL_PRAGMA => {
                let pragma_name = "";
                let pragma_args = [""; 1];
                println!(
                    "[vfs::fcntrl] Pragma {:?} was invoked with the arguments {:?}",
                    pragma_name, pragma_args
                );
                ffi::SQLITE_NOTFOUND // Allow SQLite to take over.
            }

            // May be invoked by SQLite on the database file handle shortly after it is opened in
            // order to provide a custom VFS with access to the connection's busy-handler callback.
            // Not implemented.
            ffi::SQLITE_FCNTL_BUSYHANDLER => {
                println!("[vfs::fcntrl] Handling wait handler for the VFS.");
                ffi::SQLITE_NOTFOUND
            }

            // Generate a temporary filename. Not implemented.
            ffi::SQLITE_FCNTL_TEMPFILENAME => {
                if let Some(p_arg) = (p_arg as *mut *const raw::c_char).as_mut() {
                    match state.filesystem.system.temporary_filename() {
                        Ok(name) => {
                            // unwrap() is fine as os strings are an arbitrary sequences of non-zero bytes
                            let name = CString::new(name.as_bytes()).unwrap();
                            let name = ManuallyDrop::new(name);
                            *p_arg = name.as_ptr();
                        }
                        Err(e) => {
                            println!("[vfs::fcntrl] temp-file gen failure {:?}", e);
                            return state.state.set_last_error(ffi::SQLITE_ERROR, e);
                        }
                    };

                    ffi::SQLITE_OK
                } else {
                    return state.state.set_last_error(
                        ffi::SQLITE_IOERR_READ,
                        std::io::Error::new(std::io::ErrorKind::Other, "Missing a valid path name"),
                    );
                }
            }

            // Query or set the maximum number of bytes that will be used for memory-mapped I/O.
            // Not implemented.
            ffi::SQLITE_FCNTL_MMAP_SIZE => {
                println!("[vfs::fcntrl] Adjusting (or querying) the size of memory-mapped I/O");
                ffi::SQLITE_NOTFOUND
            }

            // Advisory information to the VFS about what the higher layers of the SQLite stack are
            // doing.
            ffi::SQLITE_FCNTL_TRACE => {
                let trace = CStr::from_ptr(p_arg as *const raw::c_char);
                println!("[vfs::fcntrl] Trace: {:?}", trace);
                // log::trace!("{}", trace.to_string_lossy());
                ffi::SQLITE_OK
            }

            // Check whether or not the file has been renamed, moved, or deleted since it was first
            // opened.
            ffi::SQLITE_FCNTL_HAS_MOVED => {
                let r = get_resource_from_state!(state, ffi::SQLITE_ERROR, &state.database_name);
                match r.has_moved() {
                    Ok(moved) => {
                        if let Some(p_arg) = (p_arg as *mut i32).as_mut() {
                            *p_arg = moved as i32;
                        }
                        ffi::SQLITE_OK
                    }
                    Err(err) => state.state.set_last_error(ffi::SQLITE_ERROR, err),
                }
            }

            // Sent to the VFS immediately before the xSync method is invoked on a database file
            // descriptor. Silently ignored.
            ffi::SQLITE_FCNTL_SYNC => {
                let r = get_resource_from_state!(state, ffi::SQLITE_ERROR, &state.database_name);
                println!(
                    "[vfs::fcntrl] Requesting sync {:?} to disk.",
                    state.database_name
                );
                if let Err(err) = r.sync() {
                    println!(
                        "[vfs::fcntrl] Failed to sync {:?} to disk: {:#?}.",
                        state.database_name, err
                    );
                    state.state.set_last_error(ffi::SQLITE_ERROR, err)
                } else {
                    println!(
                        "[vfs::fcntrl] {:?} was synced to disk.",
                        state.database_name
                    );
                    ffi::SQLITE_OK
                }
            }

            // Sent to the VFS after a transaction has been committed immediately but before the
            // database is unlocked. Silently ignored.
            ffi::SQLITE_FCNTL_COMMIT_PHASETWO => {
                println!("[vfs::fcntrl] Transaction committed; prepping to unlock database.",);
                ffi::SQLITE_OK
            }

            // Used for debugging. Swap the file handle with the one pointed to by the pArg
            // argument. This capability is used during testing and only needs to be supported when
            // SQLITE_TEST is defined. Not implemented.
            ffi::SQLITE_FCNTL_WIN32_SET_HANDLE => ffi::SQLITE_NOTFOUND,

            // Signal to the VFS layer that it might be advantageous to block on the next WAL lock
            // if the lock is not immediately available. The WAL subsystem issues this signal during
            // rare circumstances in order to fix a problem with priority inversion.
            // Not implemented.
            ffi::SQLITE_FCNTL_WAL_BLOCK => {
                println!("[vfs::fcntrl] Hinting at a need to block the WAL");
                ffi::SQLITE_NOTFOUND
            }

            // Implemented by zipvfs only.
            ffi::SQLITE_FCNTL_ZIPVFS => ffi::SQLITE_NOTFOUND,

            // Implemented by the special VFS used by the RBU extension only.
            ffi::SQLITE_FCNTL_RBU => ffi::SQLITE_NOTFOUND,

            // Obtain the underlying native file handle associated with a file handle.
            // Not implemented.
            ffi::SQLITE_FCNTL_WIN32_GET_HANDLE => ffi::SQLITE_NOTFOUND,

            // Usage is not documented. Not implemented.
            ffi::SQLITE_FCNTL_PDB => ffi::SQLITE_NOTFOUND,

            // Used for "batch write mode". Not supported.
            ffi::SQLITE_FCNTL_BEGIN_ATOMIC_WRITE
            | ffi::SQLITE_FCNTL_COMMIT_ATOMIC_WRITE
            | ffi::SQLITE_FCNTL_ROLLBACK_ATOMIC_WRITE => {
                println!("[vfs::fcntrl] Handling an atomic write operation.");
                ffi::SQLITE_NOTFOUND
            }

            // Configure a VFS to block for up to M milliseconds before failing when attempting to
            // obtain a file lock using the xLock or xShmLock methods of the VFS. Not implemented.
            ffi::SQLITE_FCNTL_LOCK_TIMEOUT => {
                println!("[vfs::fcntrl] Implementing lock wait timeout.");
                ffi::SQLITE_NOTFOUND
            }

            // Used by in-memory VFS.
            ffi::SQLITE_FCNTL_SIZE_LIMIT => {
                println!("[vfs::fcntrl] in-mem vfs: size limit");
                ffi::SQLITE_NOTFOUND
            }

            // Invoked from within a checkpoint in wal mode after the client has finished copying
            // pages from the wal file to the database file, but before the *-shm file is updated to
            // record the fact that the pages have been checkpointed. Silently ignored.
            ffi::SQLITE_FCNTL_CKPT_DONE => {
                println!("[vfs::fcntrl] in-mem vfs: size limit");
                ffi::SQLITE_OK
            }

            // Invoked from within a checkpoint in wal mode before the client starts to copy pages
            // from the wal file to the database file. Silently ignored.
            ffi::SQLITE_FCNTL_CKPT_START => {
                println!("[vfs::fcntrl] in-mem vfs: size limit");
                ffi::SQLITE_OK
            }

            // Detect whether or not there is a database client in another process with a wal-mode
            // transaction open on the database or not. Not implemented because it is a
            // unix-specific feature.
            ffi::SQLITE_FCNTL_EXTERNAL_READER => {
                println!("[vfs::fcntrl] in-mem vfs: size limit");
                ffi::SQLITE_NOTFOUND
            }

            // Unknown use-case. Ignored.
            ffi::SQLITE_FCNTL_CKSM_FILE => ffi::SQLITE_NOTFOUND,

            _ => {
                println!("[vfs::fcntrl] Unhandled code: {:?}", op);
                ffi::SQLITE_NOTFOUND
            }
        }
    }

    pub unsafe extern "C" fn sector_size<F: Filesystem>(_: *mut ffi::sqlite3_file) -> raw::c_int {
        // FIXME: This should be a true bit vector.
        F::sector_size() as raw::c_int
    }
    pub unsafe extern "C" fn device_characteristics<F: Filesystem>(
        p_file: *mut ffi::sqlite3_file,
    ) -> raw::c_int {
        let state = get_state!(p_file);

        println!(
            "[vfs::device_characteristics] Fetching the device characteristics of the system that {:#?} lives on.",
            state.database_name
        );

        // after reboot following a crash or power loss, the only bytes in a file that were written
        // at the application level might have changed and that adjacent bytes, even bytes within
        // the same sector are guaranteed to be unchanged
        if state.powersafe_overwrite {
            ffi::SQLITE_IOCAP_POWERSAFE_OVERWRITE
        } else {
            0
        }
    }
    pub unsafe extern "C" fn shm_map<F: Filesystem>(
        p_file: *mut ffi::sqlite3_file,
        _region_ix: raw::c_int,
        _region_size: raw::c_int,
        _b_extend: raw::c_int,
        _pp: *mut *mut raw::c_void,
    ) -> raw::c_int {
        let _state = get_state!(p_file);
        println!("shm:map");
        ffi::SQLITE_OK
    }

    pub unsafe extern "C" fn shm_lock<F: Filesystem>(
        p_file: *mut ffi::sqlite3_file,
        _offset: raw::c_int,
        _n: raw::c_int,
        _flags: raw::c_int,
    ) -> raw::c_int {
        let _state = get_state!(p_file);
        println!("shm:lock");
        ffi::SQLITE_OK
    }

    pub unsafe extern "C" fn shm_barrier<F: Filesystem>(p_file: *mut ffi::sqlite3_file) {
        let _state = underlying_resource::<F>(p_file);
        println!("shm:barrier");
    }

    pub unsafe extern "C" fn shm_unmap<F: Filesystem>(
        p_file: *mut ffi::sqlite3_file,
        _delete_flags: raw::c_int,
    ) -> raw::c_int {
        let _state = get_state!(p_file);
        println!("shm:unmap");
        ffi::SQLITE_OK
    }
}

mod fs {
    use std::{ffi::CStr, io::ErrorKind, time::Duration};

    use super::*;

    macro_rules! get_state {
        ($f: expr, $exit_code: expr) => {
            match underlying_state::<F>($f) {
                Some(s) => s,
                None => return $exit_code,
            }
        };
        ($f: expr) => {
            match underlying_state::<F>($f) {
                Some(s) => s,
                None => return ffi::SQLITE_ERROR,
            }
        };
    }

    pub unsafe extern "C" fn open<F: Filesystem>(
        p_vfs: *mut ffi::sqlite3_vfs,
        z_name: *const raw::c_char,
        p_file: *mut ffi::sqlite3_file,
        flags: raw::c_int,
        p_out_flags: *mut raw::c_int,
    ) -> raw::c_int {
        let state = get_state!(p_vfs);

        println!("[vfs::open] Opening a file resource...");

        let name = if z_name.is_null() {
            None
        } else {
            match CStr::from_ptr(z_name).to_str() {
                Ok(name) => Some(name.to_string()),
                Err(_) => {
                    return state.set_last_error(
                        ffi::SQLITE_CANTOPEN,
                        std::io::Error::new(
                            ErrorKind::Other,
                            format!(
                                "open failed: database name must be valid utf8 (received: {:?})",
                                CStr::from_ptr(z_name)
                            ),
                        ),
                    )
                }
            }
        };

        println!("[vfs::open] Path is {:?}.", name);

        let opts = match OpenOptions::from_flags(flags) {
            Some(opts) => opts,
            None => {
                return state.set_last_error(
                    ffi::SQLITE_CANTOPEN,
                    std::io::Error::new(ErrorKind::Other, "invalid open flags"),
                );
            }
        };

        println!("[vfs::open] Flags for opening resource were {:?}.", opts);

        let out_file = match (p_file as *mut File<F>).as_mut() {
            Some(f) => f,
            None => {
                return state.set_last_error(
                    ffi::SQLITE_CANTOPEN,
                    std::io::Error::new(ErrorKind::Other, "invalid pointer to file resource"),
                );
            }
        };

        println!("[vfs::open] File handle obtained for the resource.",);

        let usable_name = name.unwrap_or_default();

        println!(
            "[vfs::open] Final path for the resource is {:?}",
            usable_name
        );

        let filesystem_resource_handle = match state.system.open(usable_name.clone(), opts.clone())
        {
            Ok(resource) => resource,
            Err(err) => {
                println!("[vfs::open] Failed to open the file {:?}", err);
                state.set_last_error(ffi::SQLITE_CANTOPEN, err);
                return ffi::SQLITE_ERROR;
            }
        };

        if let Some(p_out_flags) = p_out_flags.as_mut() {
            *p_out_flags = opts.to_flags();
        }

        out_file.base.pMethods = &state.io;
        out_file.database_name = usable_name.clone();
        out_file.resource = Some(Box::new(filesystem_resource_handle));

        println!("[vfs::open] Opened the file {:?}", usable_name);
        ffi::SQLITE_OK
    }

    pub unsafe extern "C" fn delete<F: Filesystem>(
        p_vfs: *mut ffi::sqlite3_vfs,
        z_path: *const raw::c_char,
        _sync_dir: raw::c_int,
    ) -> raw::c_int {
        let state = get_state!(p_vfs, ffi::SQLITE_DELETE);
        let path = from_cstr!(
            state,
            z_path,
            "delete failed: database path must be valid UTF-8"
        );

        match state.system.delete(path.to_string()) {
            Ok(_) => ffi::SQLITE_OK,
            Err(err) => {
                println!(
                    "[vfs::delete] Failed to delete the file {:?}: {:?}",
                    path, err
                );

                if err.kind() == ErrorKind::NotFound {
                    ffi::SQLITE_IOERR_DELETE_NOENT
                } else {
                    state.set_last_error(ffi::SQLITE_DELETE, err)
                }
            }
        }
    }

    pub unsafe extern "C" fn access<F: Filesystem>(
        p_vfs: *mut ffi::sqlite3_vfs,
        z_path: *const raw::c_char,
        flags: raw::c_int,
        p_res_out: *mut raw::c_int,
    ) -> raw::c_int {
        let state = get_state!(p_vfs);
        let path = from_cstr!(state, z_path, "access failed to construct string");
        println!(
            "[vfs::access] Checking for the flag {:?} on the file {:?}",
            flags, path
        );

        let result = match flags {
            ffi::SQLITE_ACCESS_EXISTS => {
                println!("[vfs::access] Checking if {:?} exists on disk.", path);
                state.system.exists(path)
            }
            ffi::SQLITE_ACCESS_READ => {
                println!("[vfs::access] Checking if {:?} is readable on disk.", path);
                state.system.access(path, FileAccess::Readonly)
            }
            ffi::SQLITE_ACCESS_READWRITE => {
                println!(
                    "[vfs::access] Checking if {:?} is readable and writable on disk.",
                    path
                );
                state.system.access(path, FileAccess::ReadWrite)
            }
            _ => {
                println!("[vfs::access] Unrecognized flag {:?}", flags);
                return ffi::SQLITE_IOERR_ACCESS;
            }
        };

        if let Err(err) = result.and_then(|ok| {
            let p_res_out: &mut raw::c_int = p_res_out
                .as_mut()
                .ok_or_else(|| std::io::Error::new(ErrorKind::Other, "received null pointer"))?;
            *p_res_out = ok as i32;
            println!(
                "[vfs::access] The flag {:?} for {:?} exists? [{}]",
                flags,
                path,
                ok.to_string()
            );
            Ok(())
        }) {
            println!(
                "[vfs::access] Failed to obtain access to {:?} with {:?}: {:?}",
                path, flags, err
            );
            state.set_last_error(ffi::SQLITE_IOERR_ACCESS, err)
        } else {
            ffi::SQLITE_OK
        }
    }

    pub unsafe extern "C" fn full_pathname<F: Filesystem>(
        p_vfs: *mut ffi::sqlite3_vfs,
        z_path: *const raw::c_char,
        n_out: raw::c_int,
        z_out: *mut raw::c_char,
    ) -> raw::c_int {
        let state = get_state!(p_vfs);

        println!("[vfs::full_pathname] Attempting to discern the whole path name for the provided text. ");

        let path = from_cstr!(
            state,
            z_path,
            format!(
                "full_pathname failed: database name must be valid UTF-8 (received {:?})",
                CStr::from_ptr(z_path)
            )
        );

        println!("[vfs::full_pathname] Provided path is {:?}", path);

        let name = match state.system.full_pathname(path).and_then(|name| {
            CString::new(name.to_string()).map_err(|_| {
                std::io::Error::new(ErrorKind::Other, "name must not contain a nul byte")
            })
        }) {
            Ok(name) => name,
            Err(err) => {
                println!(
                    "[vfs::full_pathname] Failed to get the true path of {:?}: {:?}",
                    path, err
                );
                return state.set_last_error(ffi::SQLITE_ERROR, err);
            }
        };

        println!("[vfs::full_pathname] Resolved path is {:?}", name);

        let name = name.to_bytes_with_nul();
        if name.len() > n_out as usize || name.len() > F::maximum_file_pathname_size() {
            println!("[vfs::full_pathname] Resolved path is too long.");
            return state.set_last_error(
                ffi::SQLITE_CANTOPEN,
                std::io::Error::new(ErrorKind::Other, "full pathname is too long"),
            );
        }

        let out = std::slice::from_raw_parts_mut(z_out as *mut u8, name.len());
        out.copy_from_slice(name);
        ffi::SQLITE_OK
    }
    pub unsafe extern "C" fn dl_open<V>(
        p_vfs: *mut ffi::sqlite3_vfs,
        z_path: *const raw::c_char,
    ) -> *mut raw::c_void {
        ptr::null_mut() as *mut raw::c_void
    }

    /// Populate the buffer `z_err_msg` (size `n_byte` bytes) with a human readable utf-8 string
    /// describing the most recent error encountered associated with dynamic libraries.
    #[allow(unused_variables)]
    pub unsafe extern "C" fn dl_error<F: Filesystem>(
        p_vfs: *mut ffi::sqlite3_vfs,
        n_byte: raw::c_int,
        z_err_msg: *mut raw::c_char,
    ) {
        let state = match underlying_state::<F>(p_vfs) {
            Some(state) => state,
            None => return,
        };

        if let Some(dlerror) = state.parent.as_ref().and_then(|v| v.xDlError) {
            return dlerror(state.parent, n_byte, z_err_msg);
        }
    }

    /// Return a pointer to the symbol `z_sym` in the dynamic library pHandle.
    #[allow(unused_variables)]
    pub unsafe extern "C" fn dl_symbol<F: Filesystem>(
        p_vfs: *mut ffi::sqlite3_vfs,
        p: *mut raw::c_void,
        z_sym: *const raw::c_char,
    ) -> Option<unsafe extern "C" fn(*mut ffi::sqlite3_vfs, *mut raw::c_void, *const raw::c_char)>
    {
        let state = match underlying_state::<F>(p_vfs) {
            Some(state) => state,
            None => return None,
        };

        state
            .parent
            .as_ref()
            .and_then(|v| v.xDlSym)
            .and_then(|dl_symbol| dl_symbol(state.parent, p, z_sym))
    }

    /// Close the dynamic library handle `p_handle`.
    #[allow(unused_variables)]
    pub unsafe extern "C" fn dl_close<F: Filesystem>(
        p_vfs: *mut ffi::sqlite3_vfs,
        p_handle: *mut raw::c_void,
    ) {
        let state = match underlying_state::<F>(p_vfs) {
            Some(state) => state,
            None => return,
        };

        if let Some(dl_close) = state.parent.as_ref().and_then(|v| v.xDlClose) {
            return dl_close(state.parent, p_handle);
        }
    }

    /// Populate the buffer pointed to by `z_buf_out` with `n_byte` bytes of random data.
    pub unsafe extern "C" fn randomness<F: Filesystem>(
        p_vfs: *mut ffi::sqlite3_vfs,
        n_byte: raw::c_int,
        z_buf_out: *mut raw::c_char,
    ) -> raw::c_int {
        let bytes = std::slice::from_raw_parts_mut(z_buf_out as *mut i8, n_byte as usize);
        let state = match underlying_state::<F>(p_vfs) {
            Some(state) => state,
            None => return 0,
        };

        state.system.random_bytes(bytes);
        bytes.len() as raw::c_int
    }

    /// Sleep for `n_micro` microseconds. Return the number of microseconds actually slept.
    pub unsafe extern "C" fn sleep<F: Filesystem>(
        p_vfs: *mut ffi::sqlite3_vfs,
        n_micro: raw::c_int,
    ) -> raw::c_int {
        let state = match underlying_state::<F>(p_vfs) {
            Some(state) => state,
            None => return ffi::SQLITE_ERROR,
        };
        state
            .system
            .sleep(Duration::from_micros(n_micro as u64))
            .as_micros() as raw::c_int
    }

    /// Return the current time as a Julian Day number in `p_time_out`.
    pub unsafe extern "C" fn current_time<F: Filesystem>(
        p_vfs: *mut ffi::sqlite3_vfs,
        p_time_out: *mut f64,
    ) -> raw::c_int {
        let mut i = 0i64;
        current_time_i64::<F>(p_vfs, &mut i);

        *p_time_out = i as f64 / 86400000.0;
        ffi::SQLITE_OK
    }

    pub unsafe extern "C" fn current_time_i64<F: Filesystem>(
        _p_vfs: *mut ffi::sqlite3_vfs,
        p: *mut i64,
    ) -> i32 {
        const UNIX_EPOCH: i64 = 24405875 * 8640000;
        let now = UNIX_EPOCH;

        *p = now;
        ffi::SQLITE_OK
    }

    pub unsafe extern "C" fn get_last_error<F: Filesystem>(
        p_vfs: *mut ffi::sqlite3_vfs,
        n_byte: raw::c_int,
        z_err_msg: *mut raw::c_char,
    ) -> raw::c_int {
        let state = match underlying_state::<F>(p_vfs) {
            Some(state) => state,
            None => return ffi::SQLITE_ERROR,
        };
        if let Some((eno, err)) = state.error.lock().unwrap().as_ref() {
            let msg = match CString::new(err.to_string()) {
                Ok(msg) => msg,
                Err(_) => return ffi::SQLITE_ERROR,
            };

            let msg = msg.to_bytes_with_nul();
            if msg.len() > n_byte as usize {
                return ffi::SQLITE_ERROR;
            }
            let out = std::slice::from_raw_parts_mut(z_err_msg as *mut u8, msg.len());
            out.copy_from_slice(msg);

            return *eno;
        }
        ffi::SQLITE_OK
    }
}

struct State<F: Filesystem> {
    name: CString,
    system: Arc<F>,
    parent: *mut ffi::sqlite3_vfs,
    io: ffi::sqlite3_io_methods,
    error: Arc<Mutex<Option<(i32, std::io::Error)>>>,
}

impl<F: Filesystem> State<F> {
    fn set_last_error(&mut self, error_code: i32, err: std::io::Error) -> i32 {
        *(self.error.lock().unwrap()) = Some((error_code, err));
        error_code
    }
}

// FIXME: Provide a return value capable of checking if it's still registered and unregistering.
/// Registers a new virtual file system to SQLite.
pub fn register<F: Filesystem>(
    vfs_name: &str,
    system: Arc<F>,
    as_default: bool,
) -> Result<(), crate::Error> {
    let io_methods = ffi::sqlite3_io_methods {
        iVersion: RUSQLITE_VFS_VERSION_IO_METHODS,
        xClose: Some(node::close::<F>),
        xRead: Some(node::read::<F>),
        xWrite: Some(node::write::<F>),
        xTruncate: Some(node::truncate::<F>),
        xSync: Some(node::sync::<F>),
        xFileSize: Some(node::file_size::<F>),
        xLock: Some(node::lock::<F>),
        xUnlock: Some(node::unlock::<F>),
        xCheckReservedLock: Some(node::check_reserved_lock::<F>),
        xFileControl: Some(node::file_control::<F>),
        xSectorSize: Some(node::sector_size::<F>),
        xDeviceCharacteristics: Some(node::device_characteristics::<F>),
        xShmMap: Some(node::shm_map::<F>),
        xShmLock: Some(node::shm_lock::<F>),
        xShmBarrier: Some(node::shm_barrier::<F>),
        xShmUnmap: Some(node::shm_unmap::<F>),
        xFetch: None,
        xUnfetch: None,
    };
    let name = CString::new(vfs_name)?;
    let name_ptr = name.as_ptr();
    let ptr = Box::into_raw(Box::new(State {
        name,
        system: Arc::clone(&system),
        parent: unsafe { ffi::sqlite3_vfs_find(ptr::null_mut()) },
        io: io_methods,
        error: Arc::new(Default::default()),
    }));
    let vfs = Box::into_raw(Box::new(ffi::sqlite3_vfs {
        iVersion: RUSQLITE_VFS_VERSION_IMPL,
        szOsFile: std::mem::size_of::<File<F>>() as raw::c_int,
        mxPathname: F::maximum_file_pathname_size() as raw::c_int,
        pNext: ptr::null_mut(),
        zName: name_ptr,
        pAppData: ptr as _,
        xOpen: Some(fs::open::<F>),
        xDelete: Some(fs::delete::<F>),
        xAccess: Some(fs::access::<F>),
        xFullPathname: Some(fs::full_pathname::<F>),
        xDlOpen: Some(fs::dl_open::<F>),
        xDlError: Some(fs::dl_error::<F>),
        xDlSym: Some(fs::dl_symbol::<F>),
        xDlClose: Some(fs::dl_close::<F>),
        xRandomness: Some(fs::randomness::<F>),
        xSleep: Some(fs::sleep::<F>),
        xCurrentTime: Some(fs::current_time::<F>),
        xGetLastError: Some(fs::get_last_error::<F>),
        xCurrentTimeInt64: Some(fs::current_time_i64::<F>),
        xSetSystemCall: None,
        xGetSystemCall: None,
        xNextSystemCall: None,
    }));

    let vfs_register_result = unsafe { ffi::sqlite3_vfs_register(vfs, as_default as raw::c_int) };
    if vfs_register_result != ffi::SQLITE_OK {
        return Err(Error::SqliteFailure(
            ffi::Error::new(vfs_register_result),
            Some("Failed to register the VFS.".to_string()),
        ));
    } else {
        Ok(())
    }
}
