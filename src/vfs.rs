// TODO: Implement the root VFS trait
// TODO: Implement a trait representing a file/resource handle.

// A lot of the work here is being cribbed from https://github.com/rkusa/sqlite-vfs/blob/main/src/lib.rs

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

pub trait Resource: Sync {}

pub trait Filesystem: Sync {
    type Handle: Resource;

    fn full_pathname<'a>(&self, pathname: &'a str) -> Result<Cow<'a, str>, std::io::Error> {
        Ok(pathname.into())
    }

    fn resource_size() -> usize {
        std::mem::size_of::<Self::Handle>()
    }

    fn maximum_file_pathname_size() -> usize {
        1024
    }

    fn random_bytes(&self, buffer: &mut [i8]);

    fn sleep(&self, duration: Duration) -> Duration;
}

static RUSQLITE_VFS_VERSION_IO_METHODS: i32 = 1;
static RUSQLITE_VFS_VERSION_IMPL: i32 = 1;

unsafe fn underlying_state<'a, F: Filesystem>(
    ptr: *mut ffi::sqlite3_vfs,
) -> Option<&'a mut State<F>> {
    let vfs: &mut ffi::sqlite3_vfs = ptr.as_mut()?;
    (vfs.pAppData as *mut State<F>).as_mut()
}

mod node {
    use super::*;

    pub unsafe extern "C" fn close<F: Filesystem>(p_file: *mut ffi::sqlite3_file) -> raw::c_int {
        ffi::SQLITE_OK
    }

    pub unsafe extern "C" fn read(
        p_file: *mut ffi::sqlite3_file,
        z_buf: *mut raw::c_void,
        i_amt: raw::c_int,
        i_ofst: ffi::sqlite3_int64,
    ) -> raw::c_int {
        ffi::SQLITE_OK
    }

    pub unsafe extern "C" fn write(
        p_file: *mut ffi::sqlite3_file,
        z: *const raw::c_void,
        i_amt: raw::c_int,
        i_ofst: ffi::sqlite3_int64,
    ) -> raw::c_int {
        ffi::SQLITE_OK
    }

    pub unsafe extern "C" fn truncate(
        p_file: *mut ffi::sqlite3_file,
        size: ffi::sqlite3_int64,
    ) -> raw::c_int {
        ffi::SQLITE_OK
    }

    pub unsafe extern "C" fn sync(p_file: *mut ffi::sqlite3_file, flags: raw::c_int) -> raw::c_int {
        ffi::SQLITE_OK
    }

    pub unsafe extern "C" fn file_size(
        p_file: *mut ffi::sqlite3_file,
        p_size: *mut ffi::sqlite3_int64,
    ) -> raw::c_int {
        ffi::SQLITE_OK
    }

    pub unsafe extern "C" fn lock(
        p_file: *mut ffi::sqlite3_file,
        e_lock: raw::c_int,
    ) -> raw::c_int {
        ffi::SQLITE_OK
    }

    pub unsafe extern "C" fn unlock(
        p_file: *mut ffi::sqlite3_file,
        e_lock: raw::c_int,
    ) -> raw::c_int {
        ffi::SQLITE_OK
    }
    pub unsafe extern "C" fn check_reserved_lock(
        p_file: *mut ffi::sqlite3_file,
        p_res_out: *mut raw::c_int,
    ) -> raw::c_int {
        ffi::SQLITE_OK
    }

    pub unsafe extern "C" fn file_control(
        p_file: *mut ffi::sqlite3_file,
        op: raw::c_int,
        p_arg: *mut raw::c_void,
    ) -> raw::c_int {
        ffi::SQLITE_OK
    }

    pub unsafe extern "C" fn sector_size(p_file: *mut ffi::sqlite3_file) -> raw::c_int {
        1024
    }
    pub unsafe extern "C" fn device_characteristics(p_file: *mut ffi::sqlite3_file) -> raw::c_int {
        ffi::SQLITE_OK
    }
    pub unsafe extern "C" fn shm_map(
        p_file: *mut ffi::sqlite3_file,
        region_ix: raw::c_int,
        region_size: raw::c_int,
        b_extend: raw::c_int,
        pp: *mut *mut raw::c_void,
    ) -> raw::c_int {
        ffi::SQLITE_OK
    }

    pub unsafe extern "C" fn shm_lock(
        p_file: *mut ffi::sqlite3_file,
        offset: raw::c_int,
        n: raw::c_int,
        flags: raw::c_int,
    ) -> raw::c_int {
        ffi::SQLITE_OK
    }

    pub unsafe extern "C" fn shm_barrier(p_file: *mut ffi::sqlite3_file) {}

    pub unsafe extern "C" fn shm_unmap(
        p_file: *mut ffi::sqlite3_file,
        delete_flags: raw::c_int,
    ) -> raw::c_int {
        ffi::SQLITE_OK
    }
}

mod fs {
    use std::time::Duration;

    use super::*;

    pub unsafe extern "C" fn open<F: Filesystem>(
        p_vfs: *mut ffi::sqlite3_vfs,
        z_name: *const raw::c_char,
        p_file: *mut ffi::sqlite3_file,
        flags: raw::c_int,
        p_out_flags: *mut raw::c_int,
    ) -> raw::c_int {
        ffi::SQLITE_OK
    }

    pub unsafe extern "C" fn delete<F: Filesystem>(
        p_vfs: *mut ffi::sqlite3_vfs,
        z_path: *const raw::c_char,
        _sync_dir: raw::c_int,
    ) -> raw::c_int {
        ffi::SQLITE_OK
    }

    pub unsafe extern "C" fn access<F: Filesystem>(
        p_vfs: *mut ffi::sqlite3_vfs,
        z_path: *const raw::c_char,
        flags: raw::c_int,
        p_res_out: *mut raw::c_int,
    ) -> raw::c_int {
        ffi::SQLITE_OK
    }

    pub unsafe extern "C" fn full_pathname<F: Filesystem>(
        p_vfs: *mut ffi::sqlite3_vfs,
        z_path: *const raw::c_char,
        n_out: raw::c_int,
        z_out: *mut raw::c_char,
    ) -> raw::c_int {
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

    pub unsafe extern "C" fn set_system_call<F: Filesystem>(
        p_vfs: *mut ffi::sqlite3_vfs,
        z_name: *const ::std::os::raw::c_char,
        p_new_func: ffi::sqlite3_syscall_ptr,
    ) -> ::std::os::raw::c_int {
        let state = match underlying_state::<F>(p_vfs) {
            Some(state) => state,
            None => return ffi::SQLITE_ERROR,
        };

        if let Some(set_system_call) = state.parent.as_ref().and_then(|v| v.xSetSystemCall) {
            return set_system_call(state.parent, z_name, p_new_func);
        }

        ffi::SQLITE_ERROR
    }

    pub unsafe extern "C" fn get_system_call<F: Filesystem>(
        p_vfs: *mut ffi::sqlite3_vfs,
        z_name: *const ::std::os::raw::c_char,
    ) -> ffi::sqlite3_syscall_ptr {
        let state = match underlying_state::<F>(p_vfs) {
            Some(state) => state,
            None => return None,
        };

        if let Some(get_system_call) = state.parent.as_ref().and_then(|v| v.xGetSystemCall) {
            return get_system_call(state.parent, z_name);
        }

        None
    }

    pub unsafe extern "C" fn next_system_call<F: Filesystem>(
        p_vfs: *mut ffi::sqlite3_vfs,
        z_name: *const ::std::os::raw::c_char,
    ) -> *const ::std::os::raw::c_char {
        if let Some(state) = underlying_state::<F>(p_vfs) {
            state
                .parent
                .as_ref()
                .and_then(|v| v.xNextSystemCall)
                .map(|c| c(state.parent, z_name))
                .unwrap_or(ptr::null())
        } else {
            ptr::null()
        }
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

// FIXME: Provide a return value capable of checking if it's still registered and unregistering.
/// Registers a new virtual file system to SQLite.
pub fn register<F: Filesystem>(
    vfs_name: impl ToString,
    system: F,
    as_default: bool,
) -> Result<(), Error> {
    let io_methods = ffi::sqlite3_io_methods {
        iVersion: RUSQLITE_VFS_VERSION_IO_METHODS,
        xClose: Some(node::close::<F>),
        xRead: Some(node::read),
        xWrite: Some(node::write),
        xTruncate: Some(node::truncate),
        xSync: Some(node::sync),
        xFileSize: Some(node::file_size),
        xLock: Some(node::lock),
        xUnlock: Some(node::unlock),
        xCheckReservedLock: Some(node::check_reserved_lock),
        xFileControl: Some(node::file_control),
        xSectorSize: Some(node::sector_size),
        xDeviceCharacteristics: Some(node::device_characteristics),
        xShmMap: Some(node::shm_map),
        xShmLock: Some(node::shm_lock),
        xShmBarrier: Some(node::shm_barrier),
        xShmUnmap: Some(node::shm_unmap),
        xFetch: None,
        xUnfetch: None,
    };
    let name = CString::new(vfs_name.to_string().as_str())?;
    let name_cstr = name.as_ptr();
    let ptr = Box::into_raw(Box::new(State {
        name: name.clone(),
        system: Arc::new(system),
        parent: unsafe { ffi::sqlite3_vfs_find(ptr::null_mut()) },
        io: io_methods,
        error: Arc::new(Default::default()),
    }));
    let vfs = Box::into_raw(Box::new(ffi::sqlite3_vfs {
        iVersion: RUSQLITE_VFS_VERSION_IMPL,
        szOsFile: F::resource_size() as raw::c_int,
        mxPathname: F::maximum_file_pathname_size() as raw::c_int,
        pNext: ptr::null_mut(),
        zName: name_cstr,
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
        xSetSystemCall: Some(fs::set_system_call::<F>),
        xGetSystemCall: Some(fs::get_system_call::<F>),
        xNextSystemCall: Some(fs::next_system_call::<F>),
    }));

    let vfs_register_result = unsafe { ffi::sqlite3_vfs_register(vfs, as_default as raw::c_int) };
    if vfs_register_result != ffi::SQLITE_OK {
        return Err(Error::SqliteFailure(
            ffi::Error::new(vfs_register_result),
            Some(format!("Failed to register the {:?} VFS.", name)),
        ));
    };

    Ok(())
}

#[cfg(test)]
mod test {
    struct MockFs {}
    struct MockHandle {}

    impl super::Resource for MockHandle {}

    impl super::Filesystem for MockFs {
        type Handle = MockHandle;

        fn random_bytes(&self, buffer: &mut [i8]) {
            todo!()
        }

        fn sleep(&self, duration: std::time::Duration) -> std::time::Duration {
            todo!()
        }
    }

    #[test]
    fn registers() {
        use super::register;

        let register_result = register("test-vfs", MockFs {}, false);
        assert!(register_result.is_ok());
    }

    #[test]
    fn generates_schema() {
        use super::register;
        let mock_fs = MockFs {};

        let register_result = register("test-vfs", mock_fs, false);
        assert_eq!(
            register_result.as_ref().err(),
            None,
            "registered vfs safely"
        );

        let conn_result = crate::Connection::open_with_flags_and_vfs(
            "mock-system.db",
            crate::OpenFlags::SQLITE_OPEN_READ_WRITE | crate::OpenFlags::SQLITE_OPEN_CREATE,
            "test-vfs",
        );

        assert_eq!(conn_result.as_ref().err(), None, "connection was opened");
    }
}
