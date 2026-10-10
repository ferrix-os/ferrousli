//! `link.h`'s `dl_iterate_phdr` and the whole of `dlfcn.h`: the loader's, when
//! `ld-ferrousli` loaded this library as `libc.so.6` (`loader.rs`), and for a static
//! program, which is the only object loaded.
//!
//! An unwinder finds the unwind tables for an address by walking the loaded
//! objects' program headers for the `PT_GNU_EH_FRAME` segment that covers it;
//! libunwind, and so every C++ exception, does exactly that. A static program
//! has one object, itself, whose headers the kernel names in the auxiliary
//! vector. Its load bias is zero for a program linked at a fixed address and
//! `AT_PHDR` less the `PT_PHDR` segment's address for a position-independent
//! one, as `thread.rs` computes it for TLS.

use core::ffi::{CStr, c_char, c_int, c_long, c_ulonglong, c_void};
use core::mem::{offset_of, size_of};
use core::ptr::{null, null_mut, with_exposed_provenance, with_exposed_provenance_mut};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::thread::Phdr;
use crate::{auxv, thread};

/// A loadable segment.
const PT_LOAD: u32 = 1;
/// The segment holding the program headers.
const PT_PHDR: u32 = 6;

/// `struct dl_phdr_info`, as `include/link.h` declares it; glibc's is the
/// same.
#[repr(C)]
#[derive(Debug)]
pub struct DlPhdrInfo {
    /// The object's load bias, C's `ElfW(Addr)`.
    pub dlpi_addr: usize,
    /// Its name; the empty string for the program itself.
    pub dlpi_name: *const c_char,
    /// Its program headers.
    pub dlpi_phdr: *const c_void,
    /// How many there are.
    pub dlpi_phnum: u16,
    /// Objects loaded since the program started, counting the program.
    pub dlpi_adds: c_ulonglong,
    /// Objects unloaded since the program started.
    pub dlpi_subs: c_ulonglong,
    /// The TLS module id: 1 for a program with a TLS segment, else 0.
    pub dlpi_tls_modid: usize,
    /// The calling thread's TLS block for the module, or null.
    pub dlpi_tls_data: *mut c_void,
}

#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<DlPhdrInfo>() == 64);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(size_of::<DlPhdrInfo>() == 40);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(offset_of!(DlPhdrInfo, dlpi_phnum) == 12);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(offset_of!(DlPhdrInfo, dlpi_adds) == 16);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(offset_of!(DlPhdrInfo, dlpi_phnum) == 24);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(offset_of!(DlPhdrInfo, dlpi_adds) == 32);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(offset_of!(DlPhdrInfo, dlpi_tls_data) == 56);

/// `Dl_info`, as `include/dlfcn.h` declares it.
#[repr(C)]
#[derive(Debug)]
pub struct DlInfo {
    /// The object's path name; empty for the program itself.
    pub dli_fname: *const c_char,
    /// The object's load address.
    pub dli_fbase: *mut c_void,
    /// The nearest symbol's name, or null.
    pub dli_sname: *const c_char,
    /// The nearest symbol's address, or null.
    pub dli_saddr: *mut c_void,
}

#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<DlInfo>() == 32);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(size_of::<DlInfo>() == 16);

/// The program's headers, from the auxiliary vector: where they are, how
/// many, and the load bias.
fn program_headers() -> Option<(*const Phdr, usize, usize)> {
    let phdr = auxv::get(auxv::AT_PHDR)?;
    let phent = auxv::get(auxv::AT_PHENT)?;
    let phnum = auxv::get(auxv::AT_PHNUM)?;
    if phent != size_of::<Phdr>() {
        return None;
    }
    let mut bias = 0_usize;
    let mut i = 0;
    while i < phnum {
        // SAFETY: the kernel mapped `phnum` headers at `AT_PHDR`.
        let header = unsafe { header(phdr, i) };
        if header.p_type == PT_PHDR {
            bias = phdr.wrapping_sub(header.p_vaddr as usize);
        }
        i += 1;
    }
    Some((with_exposed_provenance(phdr), phnum, bias))
}

/// The `i`th program header at `phdr`.
///
/// # Safety
///
/// At least `i + 1` headers must be mapped at `phdr`.
unsafe fn header(phdr: usize, i: usize) -> Phdr {
    let at = with_exposed_provenance::<Phdr>(phdr.wrapping_add(i.wrapping_mul(size_of::<Phdr>())));
    // SAFETY: the caller vouches for the header.
    unsafe { at.read_unaligned() }
}

/// The type of `dl_iterate_phdr`'s callback.
pub type Callback = unsafe extern "C" fn(*mut DlPhdrInfo, usize, *mut c_void) -> c_int;

/// Calls `callback` once for each loaded object, which in a static program is
/// the program, with `data`, and returns what the last call returned. Returns
/// 0 without calling it if the kernel gave no program headers.
///
/// # Safety
///
/// `callback` must be safe to call with a `DlPhdrInfo` it may read and `data`.
#[cfg_attr(not(test), unsafe(no_mangle))]
pub unsafe extern "C" fn dl_iterate_phdr(callback: Option<Callback>, data: *mut c_void) -> c_int {
    if let Some(loader) = crate::loader::dlfcn() {
        // SAFETY: the caller's contract is the loader's.
        return unsafe { (loader.dl_iterate_phdr)(callback, data) };
    }
    let (Some(callback), Some((phdr, phnum, bias))) = (callback, program_headers()) else {
        return 0;
    };
    let tls = thread::tls_block();
    let mut info = DlPhdrInfo {
        dlpi_addr: bias,
        dlpi_name: c"".as_ptr(),
        dlpi_phdr: phdr.cast(),
        dlpi_phnum: u16::try_from(phnum).unwrap_or(u16::MAX),
        dlpi_adds: 1,
        dlpi_subs: 0,
        dlpi_tls_modid: usize::from(tls.is_some()),
        dlpi_tls_data: tls.unwrap_or(null_mut()),
    };
    // SAFETY: the caller vouches for the callback; `info` lives across it.
    unsafe { callback(&raw mut info, size_of::<DlPhdrInfo>(), data) }
}

/// Describes the object holding `address`: in a static program, the program
/// when a loadable segment covers the address, with no symbol, since the
/// program carries no dynamic symbol table to name one from. Returns nonzero
/// when `info` was filled, and 0 for an address outside the program.
///
/// # Safety
///
/// `info` must be valid to write a `Dl_info` to.
#[cfg_attr(not(test), unsafe(no_mangle))]
pub unsafe extern "C" fn dladdr(address: *const c_void, info: *mut DlInfo) -> c_int {
    if let Some(loader) = crate::loader::dlfcn() {
        // SAFETY: the caller's contract is the loader's.
        return unsafe { (loader.dladdr)(address, info) };
    }
    let Some((phdr, phnum, bias)) = program_headers() else {
        return 0;
    };
    let wanted = address.addr();
    let mut i = 0;
    while i < phnum {
        // SAFETY: `program_headers` counted `phnum` headers at `phdr`.
        let header = unsafe { header(phdr.addr(), i) };
        let start = bias.wrapping_add(header.p_vaddr as usize);
        if header.p_type == PT_LOAD
            && wanted >= start
            && wanted - start < usize::try_from(header.p_memsz).unwrap_or(0)
        {
            // SAFETY: the caller vouches for `info`.
            unsafe {
                info.write(DlInfo {
                    dli_fname: c"".as_ptr(),
                    dli_fbase: with_exposed_provenance::<c_void>(bias).cast_mut(),
                    dli_sname: null(),
                    dli_saddr: null_mut(),
                });
            }
            return 1;
        }
        i += 1;
    }
    0
}

/// Loads a shared object: never, in a static program. Returns null, and
/// [`dlerror`] then says why, as musl's static `dlopen` does.
///
/// # Safety
///
/// `path` must be null or a NUL-terminated string.
#[cfg_attr(not(test), unsafe(no_mangle))]
pub unsafe extern "C" fn dlopen(path: *const c_char, flags: c_int) -> *mut c_void {
    if let Some(loader) = crate::loader::dlfcn() {
        // SAFETY: the caller's contract is the loader's.
        return unsafe { (loader.dlopen)(path, flags) };
    }
    fail();
    null_mut()
}

/// Looks a symbol up in a loaded object. A static program has loaded none, so
/// this finds nothing and returns null, as musl's static `dlsym` does.
///
/// Rust's `std` calls this to find functions it can do without, and takes null
/// as "the C library has not got it"; that is how this came to be needed.
///
/// `dlsym` itself is a few instructions of assembly per architecture, below,
/// that pass its return address on as `caller`: `RTLD_NEXT` means "after the
/// object that called", which only the return address can say. Chrome finds
/// the C library's `close` that way, having defined its own.
///
/// # Safety
///
/// `name` must be a NUL-terminated string.
#[cfg_attr(test, allow(dead_code, reason = "tests reach it through `dlsym`"))]
pub(crate) unsafe extern "C" fn dlsym_caller(
    handle: *mut c_void,
    name: *const c_char,
    caller: *const c_void,
) -> *mut c_void {
    if let Some(dlsym_from) = crate::loader::dlsym_from() {
        // SAFETY: the caller's contract is the loader's.
        return unsafe { dlsym_from(handle, name, caller) };
    }
    if let Some(loader) = crate::loader::dlfcn() {
        // SAFETY: as above.
        return unsafe { (loader.dlsym)(handle, name) };
    }
    fail();
    null_mut()
}

/// [`dlsym_caller`] with no caller known, as unit tests call it.
///
/// # Safety
///
/// `name` must be a NUL-terminated string.
#[cfg(test)]
pub unsafe extern "C" fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { dlsym_caller(handle, name, null_mut()) }
}

// `dlsym`: the return address becomes the third argument, and the rest is
// [`dlsym_caller`]'s, reached by a tail call so that it returns straight to
// the program.
#[cfg(all(not(test), target_arch = "x86_64"))]
core::arch::global_asm!(
    ".pushsection .text.dlsym,\"ax\",@progbits",
    ".p2align 4",
    ".globl dlsym",
    ".type dlsym, @function",
    "dlsym:",
    "    mov rdx, qword ptr [rsp]",
    "    jmp {target}",
    ".size dlsym, . - dlsym",
    ".popsection",
    target = sym dlsym_caller,
);

#[cfg(all(not(test), target_arch = "aarch64"))]
core::arch::global_asm!(
    ".pushsection .text.dlsym,\"ax\",%progbits",
    ".p2align 2",
    ".globl dlsym",
    ".type dlsym, %function",
    "dlsym:",
    "    mov x2, x30",
    "    b {target}",
    ".size dlsym, . - dlsym",
    ".popsection",
    target = sym dlsym_caller,
);

#[cfg(all(not(test), target_arch = "arm"))]
core::arch::global_asm!(
    ".pushsection .text.dlsym,\"ax\",%progbits",
    ".p2align 2",
    ".globl dlsym",
    ".type dlsym, %function",
    "dlsym:",
    "    mov r2, lr",
    "    b {target}",
    ".size dlsym, . - dlsym",
    ".popsection",
    target = sym dlsym_caller,
);

/// `dlvsym`'s work, as [`dlsym_caller`] is `dlsym`'s: `name` at `version`,
/// with the return address as `caller` for `RTLD_NEXT`. A static program has
/// loaded nothing and finds nothing; a loader older than revision 5 is asked
/// for the name at any version, the best it can answer.
///
/// # Safety
///
/// `name` and `version` must be NUL-terminated strings.
#[cfg_attr(test, allow(dead_code, reason = "reached through the assembly below"))]
pub(crate) unsafe extern "C" fn dlvsym_caller(
    handle: *mut c_void,
    name: *const c_char,
    version: *const c_char,
    caller: *const c_void,
) -> *mut c_void {
    if let Some(dlvsym_from) = crate::loader::dlvsym_from() {
        // SAFETY: the caller's contract is the loader's.
        return unsafe { dlvsym_from(handle, name, version, caller) };
    }
    // SAFETY: as above, without the version.
    unsafe { dlsym_caller(handle, name, caller) }
}

// `dlvsym`: the return address becomes the fourth argument, as `dlsym`'s
// becomes its third.
#[cfg(all(not(test), target_arch = "x86_64"))]
core::arch::global_asm!(
    ".pushsection .text.dlvsym,\"ax\",@progbits",
    ".p2align 4",
    ".globl dlvsym",
    ".type dlvsym, @function",
    "dlvsym:",
    "    mov rcx, qword ptr [rsp]",
    "    jmp {target}",
    ".size dlvsym, . - dlvsym",
    ".popsection",
    target = sym dlvsym_caller,
);

#[cfg(all(not(test), target_arch = "aarch64"))]
core::arch::global_asm!(
    ".pushsection .text.dlvsym,\"ax\",%progbits",
    ".p2align 2",
    ".globl dlvsym",
    ".type dlvsym, %function",
    "dlvsym:",
    "    mov x3, x30",
    "    b {target}",
    ".size dlvsym, . - dlvsym",
    ".popsection",
    target = sym dlvsym_caller,
);

#[cfg(all(not(test), target_arch = "arm"))]
core::arch::global_asm!(
    ".pushsection .text.dlvsym,\"ax\",%progbits",
    ".p2align 2",
    ".globl dlvsym",
    ".type dlvsym, %function",
    "dlvsym:",
    "    mov r3, lr",
    "    b {target}",
    ".size dlvsym, . - dlvsym",
    ".popsection",
    target = sym dlvsym_caller,
);

/// `LM_ID_BASE`, from `dlfcn.h`: the namespace the program was loaded in.
const LM_ID_BASE: c_long = 0;

/// `LM_ID_NEWLM`: a namespace of its own for what is opened.
const LM_ID_NEWLM: c_long = -1;

/// [`dlopen`] into the link-map namespace `lmid`: glibc's `dlmopen`. The
/// loader has one namespace, the program's, so `LM_ID_BASE` is exactly
/// `dlopen`, and `LM_ID_NEWLM` opens the object there too, sharing the
/// libraries already loaded where glibc would load fresh copies of them.
/// Any other namespace is not one there can be, and fails as a failed
/// `dlopen` does. The Steam client's browser helper and its `tier0` library
/// open with it.
///
/// # Safety
///
/// As [`dlopen`].
#[cfg_attr(not(test), unsafe(no_mangle))]
pub unsafe extern "C" fn dlmopen(lmid: c_long, path: *const c_char, flags: c_int) -> *mut c_void {
    if lmid != LM_ID_BASE && lmid != LM_ID_NEWLM {
        fail();
        return null_mut();
    }
    // SAFETY: the caller's contract is `dlopen`'s.
    unsafe { dlopen(path, flags) }
}

/// Closes a handle from [`dlopen`], which in a static program never gave one
/// out, and returns -1. Loaded by `ld-ferrousli`, the loader's.
#[cfg_attr(not(test), unsafe(no_mangle))]
pub extern "C" fn dlclose(handle: *mut c_void) -> c_int {
    if let Some(loader) = crate::loader::dlfcn() {
        return (loader.dlclose)(handle);
    }
    fail();
    -1
}

/// The message for the last `dlfcn.h` call that failed, or null if none has
/// since this was last called. In a static program every call fails the same
/// way; loaded by `ld-ferrousli`, the loader keeps the message.
#[cfg_attr(not(test), unsafe(no_mangle))]
pub extern "C" fn dlerror() -> *mut c_char {
    if let Some(loader) = crate::loader::dlfcn() {
        return (loader.dlerror)();
    }
    if FAILED.swap(false, Ordering::Relaxed) {
        MESSAGE.as_ptr().cast_mut()
    } else {
        null_mut()
    }
}

/// Whether a `dlfcn.h` call has failed since [`dlerror`] last reported one.
static FAILED: AtomicBool = AtomicBool::new(false);

/// What [`dlerror`] says. musl's static build says the same.
const MESSAGE: &CStr = c"Dynamic loading not supported";

/// Records that a `dlfcn.h` call failed, for [`dlerror`] to report.
fn fail() {
    FAILED.store(true, Ordering::Relaxed);
}

/// The segment naming an object's unwind table: its `.eh_frame_hdr`.
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;

/// `struct dl_find_object`, as `include/dlfcn.h` declares it for the 64-bit
/// targets, and as glibc 2.35 and later lay it out there: 96 bytes, with no
/// `dlfo_eh_dbase` and no `dlfo_eh_count`, which only i386 and 32-bit Arm
/// have. libgcc's unwinder is compiled against this layout and passes one on
/// its stack.
#[cfg(target_pointer_width = "64")]
#[repr(C)]
#[derive(Debug)]
pub struct DlFindObject {
    /// Flags: none are defined, and 0 is written.
    pub dlfo_flags: c_ulonglong,
    /// The lowest address any loadable segment of the object is mapped at.
    pub dlfo_map_start: *mut c_void,
    /// One past the highest.
    pub dlfo_map_end: *mut c_void,
    /// The object's `struct link_map`. Null here: the unwinder does not read
    /// it, and `dladdr1` and `dlinfo` are the ways to one.
    pub dlfo_link_map: *mut c_void,
    /// The object's `PT_GNU_EH_FRAME` segment, or null when it has none.
    pub dlfo_eh_frame: *mut c_void,
    /// Kept for later fields, and left as the caller had it.
    pub dlfo_reserved: [c_ulonglong; 7],
}

#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<DlFindObject>() == 96);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(offset_of!(DlFindObject, dlfo_map_start) == 8);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(offset_of!(DlFindObject, dlfo_eh_frame) == 32);

/// What [`covering`] looks for and what it found.
#[cfg(target_pointer_width = "64")]
struct Search {
    /// The address asked about.
    address: usize,
    /// The bounds of the object that holds it, and its unwind table.
    start: usize,
    end: usize,
    eh_frame: usize,
}

/// A [`dl_iterate_phdr`] callback: when a loadable segment of this object
/// covers the address in the [`Search`] at `data`, write the object's bounds
/// and its unwind table there and stop the walk with 1.
///
/// # Safety
///
/// `info` must describe a loaded object, as `dl_iterate_phdr` passes it, and
/// `data` must point to a [`Search`].
#[cfg(target_pointer_width = "64")]
unsafe extern "C" fn covering(info: *mut DlPhdrInfo, _size: usize, data: *mut c_void) -> c_int {
    // SAFETY: the caller vouches for `data`, which nothing else holds while
    // the walk runs.
    let search = unsafe { &mut *data.cast::<Search>() };
    // SAFETY: the caller vouches for `info`.
    let info = unsafe { &*info };
    let (bias, phdr, phnum, address) = (
        info.dlpi_addr,
        info.dlpi_phdr.expose_provenance(),
        usize::from(info.dlpi_phnum),
        search.address,
    );
    let (mut low, mut high, mut eh_frame, mut covers) = (usize::MAX, 0_usize, 0_usize, false);
    let mut i = 0;
    while i < phnum {
        // SAFETY: the object has `phnum` headers mapped at `phdr`.
        let header = unsafe { header(phdr, i) };
        let start = bias.wrapping_add(header.p_vaddr as usize);
        let end = start.wrapping_add(header.p_memsz as usize);
        if header.p_type == PT_LOAD {
            if start < low {
                low = start;
            }
            if end > high {
                high = end;
            }
            if address >= start && address < end {
                covers = true;
            }
        } else if header.p_type == PT_GNU_EH_FRAME {
            eh_frame = start;
        }
        i += 1;
    }
    if !covers {
        return 0;
    }
    search.start = low;
    search.end = high;
    search.eh_frame = eh_frame;
    1
}

/// Describes the loaded object holding `address` for an unwinder, as glibc
/// 2.35 and later do: 0 with `*result` filled, or -1 when no loaded object
/// holds the address.
///
/// The caller is `_Unwind_Find_FDE` in libgcc, and since GCC 12 this is the
/// only question it asks where the C library declares the function: told -1
/// it gives up rather than walk [`dl_iterate_phdr`] itself, the exception
/// finds no handler, and the program aborts. Until 2026-10-11 this answered
/// -1 always, taking the walk for a fallback, and so no Rust program built for
/// glibc could catch a panic on `ld-ferrousli`: `cargo test` ended at the
/// first failing test with `SIGABRT`, and rust-analyzer, which cancels a query
/// by unwinding, ended with no message at its second request.
///
/// The answer is found by the walk the unwinder used to make: the object with
/// a loadable segment over the address, its lowest and highest mapped
/// addresses, and its `PT_GNU_EH_FRAME` segment. The link map is left null.
///
/// On the 32-bit targets the structure has a field more (the i386 table's
/// base, Arm's `PT_ARM_EXIDX` count) and Arm's unwinder asks
/// `__gnu_Unwind_Find_exidx` instead; there this still answers -1.
///
/// # Safety
///
/// `result` must be valid to write a `struct dl_find_object` to.
#[cfg(target_pointer_width = "64")]
#[cfg_attr(not(test), unsafe(no_mangle))]
pub unsafe extern "C" fn _dl_find_object(address: *mut c_void, result: *mut DlFindObject) -> c_int {
    if result.is_null() {
        return -1;
    }
    let mut search = Search {
        address: address.expose_provenance(),
        start: 0,
        end: 0,
        eh_frame: 0,
    };
    // SAFETY: `covering` is given what `dl_iterate_phdr` passes a callback,
    // and `search` lives across the walk.
    let found = unsafe { dl_iterate_phdr(Some(covering), (&raw mut search).cast()) };
    if found != 1 {
        return -1;
    }
    // SAFETY: the caller vouches for `result`. Each field is then written in
    // place, so the reserved words stay as they were.
    let result = unsafe { &mut *result };
    result.dlfo_flags = 0;
    result.dlfo_map_start = with_exposed_provenance_mut(search.start);
    result.dlfo_map_end = with_exposed_provenance_mut(search.end);
    result.dlfo_link_map = null_mut();
    result.dlfo_eh_frame = with_exposed_provenance_mut(search.eh_frame);
    0
}

/// As above, for the 32-bit targets: always -1 (see the 64-bit one).
///
/// # Safety
///
/// None: neither pointer is read or written.
#[cfg(target_pointer_width = "32")]
#[cfg_attr(not(test), unsafe(no_mangle))]
pub extern "C" fn _dl_find_object(_address: *mut c_void, _result: *mut c_void) -> c_int {
    -1
}
