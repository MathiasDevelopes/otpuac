use windows_sys::Win32::Foundation::LocalFree;

pub(super) struct LocalAllocPtr(pub(super) *mut core::ffi::c_void);

impl Drop for LocalAllocPtr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}
