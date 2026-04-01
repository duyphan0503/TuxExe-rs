#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! Minimal Winsock (`ws2_32.dll`) implementation backed by Linux sockets.

use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void};
use std::mem;
use std::ptr;
use std::sync::{OnceLock, RwLock};

use tracing::{trace, warn};

use crate::nt_kernel::sync as nt_sync;
use crate::utils::handle::{global_table, init_global_table, Handle, INVALID_HANDLE_VALUE};

const INVALID_SOCKET: usize = usize::MAX;
const SOCKET_ERROR: i32 = -1;
const OVERLAPPED_WAIT_TIMEOUT_MS: i32 = 30_000;

const WINSOCK_FD_SETSIZE: usize = 64;

const FD_READ: i32 = 0x01;
const FD_WRITE: i32 = 0x02;
const FD_OOB: i32 = 0x04;
const FD_ACCEPT: i32 = 0x08;
const FD_CONNECT: i32 = 0x10;
const FD_CLOSE: i32 = 0x20;

const WSA_IO_INCOMPLETE: i32 = 996;
const WSA_IO_PENDING: i32 = 997;

const WSANO_DATA: i32 = 11004;
const WSAEINTR: i32 = 10004;
const WSAEBADF: i32 = 10009;
const WSAEACCES: i32 = 10013;
const WSAEFAULT: i32 = 10014;
const WSAEINVAL: i32 = 10022;
const WSAEMFILE: i32 = 10024;
const WSAEWOULDBLOCK: i32 = 10035;
const WSAEINPROGRESS: i32 = 10036;
const WSAEALREADY: i32 = 10037;
const WSAENOTSOCK: i32 = 10038;
const WSAEDESTADDRREQ: i32 = 10039;
const WSAEMSGSIZE: i32 = 10040;
const WSAEPROTOTYPE: i32 = 10041;
const WSAENOPROTOOPT: i32 = 10042;
const WSAEPROTONOSUPPORT: i32 = 10043;
const WSAEAFNOSUPPORT: i32 = 10047;
const WSAEADDRINUSE: i32 = 10048;
const WSAEADDRNOTAVAIL: i32 = 10049;
const WSAENETDOWN: i32 = 10050;
const WSAENETUNREACH: i32 = 10051;
const WSAENETRESET: i32 = 10052;
const WSAECONNABORTED: i32 = 10053;
const WSAECONNRESET: i32 = 10054;
const WSAENOBUFS: i32 = 10055;
const WSAEISCONN: i32 = 10056;
const WSAENOTCONN: i32 = 10057;
const WSAETIMEDOUT: i32 = 10060;
const WSAECONNREFUSED: i32 = 10061;
const WSAEHOSTUNREACH: i32 = 10065;

#[repr(C)]
pub struct WsaData {
    pub wVersion: u16,
    pub wHighVersion: u16,
    pub iMaxSockets: u16,
    pub iMaxUdpDg: u16,
    pub lpVendorInfo: *mut c_char,
    pub szDescription: [c_char; 257],
    pub szSystemStatus: [c_char; 129],
}

#[repr(C)]
pub struct WinFdSet {
    fd_count: u32,
    fd_array: [usize; WINSOCK_FD_SETSIZE],
}

#[repr(C)]
pub struct WinTimeVal {
    tv_sec: i32,
    tv_usec: i32,
}

#[repr(C)]
pub struct WsaBuf {
    pub len: u32,
    pub buf: *mut c_char,
}

#[repr(C)]
pub struct WsaOverlapped {
    pub Internal: usize,
    pub InternalHigh: usize,
    pub Offset: u32,
    pub OffsetHigh: u32,
    pub hEvent: Handle,
}

type WsaOverlappedCompletionRoutine = unsafe extern "win64" fn(u32, u32, *mut WsaOverlapped, u32);
pub type AsyncSelectCallback = extern "C" fn(usize, u32, usize, i32, i32);

thread_local! {
    static WSA_LAST_ERROR: std::cell::Cell<i32> = const { std::cell::Cell::new(0) };
}

#[derive(Clone, Copy, Debug)]
enum AsyncNotifyMode {
    Message { hwnd: usize, msg: u32 },
    Event { event_handle: Handle },
}

#[derive(Clone, Copy, Debug)]
struct AsyncRegistration {
    event_mask: i32,
    notify: AsyncNotifyMode,
}

#[derive(Debug)]
struct AsyncSelectRuntime {
    epoll_fd: c_int,
    registrations: RwLock<HashMap<usize, AsyncRegistration>>,
    callback: RwLock<Option<AsyncSelectCallback>>,
}

static ASYNC_RUNTIME: OnceLock<AsyncSelectRuntime> = OnceLock::new();

fn map_errno_to_wsa(errno: i32) -> i32 {
    match errno {
        x if x == libc::EINTR => WSAEINTR,
        x if x == libc::EBADF => WSAEBADF,
        x if x == libc::EACCES => WSAEACCES,
        x if x == libc::EFAULT => WSAEFAULT,
        x if x == libc::EINVAL => WSAEINVAL,
        x if x == libc::EMFILE => WSAEMFILE,
        x if x == libc::EWOULDBLOCK || x == libc::EAGAIN => WSAEWOULDBLOCK,
        x if x == libc::EINPROGRESS => WSAEINPROGRESS,
        x if x == libc::EALREADY => WSAEALREADY,
        x if x == libc::ENOTSOCK => WSAENOTSOCK,
        x if x == libc::EDESTADDRREQ => WSAEDESTADDRREQ,
        x if x == libc::EMSGSIZE => WSAEMSGSIZE,
        x if x == libc::EPROTOTYPE => WSAEPROTOTYPE,
        x if x == libc::ENOPROTOOPT => WSAENOPROTOOPT,
        x if x == libc::EPROTONOSUPPORT => WSAEPROTONOSUPPORT,
        x if x == libc::EAFNOSUPPORT => WSAEAFNOSUPPORT,
        x if x == libc::EADDRINUSE => WSAEADDRINUSE,
        x if x == libc::EADDRNOTAVAIL => WSAEADDRNOTAVAIL,
        x if x == libc::ENETDOWN => WSAENETDOWN,
        x if x == libc::ENETUNREACH => WSAENETUNREACH,
        x if x == libc::ENETRESET => WSAENETRESET,
        x if x == libc::ECONNABORTED => WSAECONNABORTED,
        x if x == libc::ECONNRESET => WSAECONNRESET,
        x if x == libc::ENOBUFS => WSAENOBUFS,
        x if x == libc::EISCONN => WSAEISCONN,
        x if x == libc::ENOTCONN => WSAENOTCONN,
        x if x == libc::ETIMEDOUT => WSAETIMEDOUT,
        x if x == libc::ECONNREFUSED => WSAECONNREFUSED,
        x if x == libc::EHOSTUNREACH => WSAEHOSTUNREACH,
        _ => WSAEINVAL,
    }
}

fn set_wsa_last_error(code: i32) {
    WSA_LAST_ERROR.with(|cell| cell.set(code));
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EINVAL)
}

fn set_wsa_error_from_errno() {
    set_wsa_last_error(map_errno_to_wsa(last_errno()));
}

fn epoll_mask_from_network_events(events: i32) -> Option<u32> {
    if events == 0 {
        return None;
    }

    let mut epoll_events: u32 = 0;

    if events & (FD_READ | FD_ACCEPT | FD_CLOSE) != 0 {
        epoll_events |= libc::EPOLLIN as u32;
        epoll_events |= libc::EPOLLRDHUP as u32;
    }
    if events & (FD_WRITE | FD_CONNECT) != 0 {
        epoll_events |= libc::EPOLLOUT as u32;
    }
    if events & FD_OOB != 0 {
        epoll_events |= libc::EPOLLPRI as u32;
    }

    epoll_events |= libc::EPOLLERR as u32;
    epoll_events |= libc::EPOLLHUP as u32;
    Some(epoll_events)
}

fn network_events_from_epoll(epoll_events: u32) -> i32 {
    let mut events = 0;

    if epoll_events & (libc::EPOLLIN as u32) != 0 {
        events |= FD_READ | FD_ACCEPT;
    }
    if epoll_events & (libc::EPOLLOUT as u32) != 0 {
        events |= FD_WRITE | FD_CONNECT;
    }
    if epoll_events & (libc::EPOLLPRI as u32) != 0 {
        events |= FD_OOB;
    }
    if epoll_events
        & ((libc::EPOLLHUP as u32) | (libc::EPOLLRDHUP as u32) | (libc::EPOLLERR as u32))
        != 0
    {
        events |= FD_CLOSE;
    }

    events
}

fn socket_wsa_error(socket: usize) -> i32 {
    let mut so_error: c_int = 0;
    let mut len = mem::size_of::<c_int>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            socket as c_int,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&raw mut so_error).cast::<c_void>(),
            &raw mut len,
        )
    };

    if ret == 0 && so_error != 0 {
        map_errno_to_wsa(so_error)
    } else {
        0
    }
}

fn set_socket_nonblocking(socket: usize, nonblocking: bool) -> Result<(), i32> {
    let fd = socket as c_int;
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(map_errno_to_wsa(last_errno()));
    }

    let updated = if nonblocking { flags | libc::O_NONBLOCK } else { flags & !libc::O_NONBLOCK };
    if unsafe { libc::fcntl(fd, libc::F_SETFL, updated) } < 0 {
        return Err(map_errno_to_wsa(last_errno()));
    }

    Ok(())
}

fn wait_socket_epoll(socket: usize, epoll_events: u32, timeout_ms: i32) -> Result<(), i32> {
    let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epoll_fd < 0 {
        return Err(map_errno_to_wsa(last_errno()));
    }

    let mut event = libc::epoll_event {
        events: epoll_events | (libc::EPOLLERR as u32) | (libc::EPOLLHUP as u32),
        u64: socket as u64,
    };
    let add_ret =
        unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, socket as c_int, &raw mut event) };
    if add_ret < 0 {
        let err = map_errno_to_wsa(last_errno());
        let _ = unsafe { libc::close(epoll_fd) };
        return Err(err);
    }

    let mut ready: libc::epoll_event = unsafe { mem::zeroed() };
    let wait_ret = unsafe { libc::epoll_wait(epoll_fd, &raw mut ready, 1, timeout_ms) };
    let _ = unsafe { libc::close(epoll_fd) };

    if wait_ret == 0 {
        return Err(WSAETIMEDOUT);
    }
    if wait_ret < 0 {
        return Err(map_errno_to_wsa(last_errno()));
    }

    if ready.events
        & ((libc::EPOLLERR as u32) | (libc::EPOLLHUP as u32) | (libc::EPOLLRDHUP as u32))
        != 0
    {
        let err = socket_wsa_error(socket);
        if err != 0 {
            return Err(err);
        }
    }

    Ok(())
}

fn is_would_block(err: i32) -> bool {
    err == WSAEWOULDBLOCK || err == WSAEINPROGRESS || err == WSAEALREADY
}

impl AsyncSelectRuntime {
    fn new() -> Result<Self, i32> {
        let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epoll_fd < 0 {
            return Err(map_errno_to_wsa(last_errno()));
        }

        Ok(Self {
            epoll_fd,
            registrations: RwLock::new(HashMap::new()),
            callback: RwLock::new(None),
        })
    }

    fn spawn_worker(&'static self) {
        let result = std::thread::Builder::new()
            .name("ws2_32-epoll".to_string())
            .spawn(move || self.worker_loop());
        if let Err(err) = result {
            warn!(%err, "Failed to spawn ws2_32 async worker thread");
        }
    }

    fn worker_loop(&self) {
        let mut events: [libc::epoll_event; 64] = unsafe { mem::zeroed() };

        loop {
            let count = unsafe {
                libc::epoll_wait(self.epoll_fd, events.as_mut_ptr(), events.len() as c_int, 250)
            };

            if count < 0 {
                let errno = last_errno();
                if errno == libc::EINTR {
                    continue;
                }
                warn!(errno, "epoll_wait failed in ws2_32 async worker");
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }

            for event in events.iter().take(count as usize) {
                let socket = event.u64 as usize;
                let registration = self
                    .registrations
                    .read()
                    .expect("async registration table poisoned")
                    .get(&socket)
                    .copied();

                let Some(registration) = registration else {
                    continue;
                };

                let mask = network_events_from_epoll(event.events) & registration.event_mask;
                if mask == 0 {
                    continue;
                }

                let error = if event.events
                    & ((libc::EPOLLERR as u32)
                        | (libc::EPOLLHUP as u32)
                        | (libc::EPOLLRDHUP as u32))
                    != 0
                {
                    socket_wsa_error(socket)
                } else {
                    0
                };

                match registration.notify {
                    AsyncNotifyMode::Message { hwnd, msg } => {
                        let callback = *self.callback.read().expect("async callback lock poisoned");
                        if let Some(cb) = callback {
                            cb(hwnd, msg, socket, mask, error);
                        }
                    }
                    AsyncNotifyMode::Event { event_handle } => {
                        let _ = nt_sync::set_event(event_handle);
                    }
                }
            }
        }
    }

    fn register(&self, socket: usize, event_mask: i32, notify: AsyncNotifyMode) -> Result<(), i32> {
        let Some(epoll_mask) = epoll_mask_from_network_events(event_mask) else {
            return Err(WSAEINVAL);
        };

        set_socket_nonblocking(socket, true)?;

        let mut event = libc::epoll_event { events: epoll_mask, u64: socket as u64 };
        let mut registrations =
            self.registrations.write().expect("async registration table poisoned");
        let op = if registrations.contains_key(&socket) {
            libc::EPOLL_CTL_MOD
        } else {
            libc::EPOLL_CTL_ADD
        };

        let mut ctl_ret =
            unsafe { libc::epoll_ctl(self.epoll_fd, op, socket as c_int, &raw mut event) };
        if ctl_ret < 0 && op == libc::EPOLL_CTL_ADD && last_errno() == libc::EEXIST {
            ctl_ret = unsafe {
                libc::epoll_ctl(self.epoll_fd, libc::EPOLL_CTL_MOD, socket as c_int, &raw mut event)
            };
        }
        if ctl_ret < 0 {
            return Err(map_errno_to_wsa(last_errno()));
        }

        registrations.insert(socket, AsyncRegistration { event_mask, notify });
        Ok(())
    }

    fn unregister(&self, socket: usize) {
        let mut registrations =
            self.registrations.write().expect("async registration table poisoned");
        if registrations.remove(&socket).is_some() {
            let mut event = libc::epoll_event { events: 0, u64: socket as u64 };
            let _ = unsafe {
                libc::epoll_ctl(self.epoll_fd, libc::EPOLL_CTL_DEL, socket as c_int, &raw mut event)
            };
        }
    }
}

fn get_async_runtime() -> Option<&'static AsyncSelectRuntime> {
    ASYNC_RUNTIME.get()
}

fn get_or_init_async_runtime() -> Result<&'static AsyncSelectRuntime, i32> {
    if let Some(runtime) = get_async_runtime() {
        return Ok(runtime);
    }

    let runtime = AsyncSelectRuntime::new()?;
    match ASYNC_RUNTIME.set(runtime) {
        Ok(()) => {
            let runtime = ASYNC_RUNTIME.get().expect("runtime must be initialized");
            runtime.spawn_worker();
            Ok(runtime)
        }
        Err(_) => Ok(ASYNC_RUNTIME.get().expect("runtime should exist after init race")),
    }
}

fn register_async_socket(
    socket: usize,
    event_mask: i32,
    notify: AsyncNotifyMode,
) -> Result<(), i32> {
    let runtime = get_or_init_async_runtime()?;
    runtime.register(socket, event_mask, notify)
}

fn unregister_async_socket(socket: usize) {
    if let Some(runtime) = get_async_runtime() {
        runtime.unregister(socket);
    }
}

pub extern "win64" fn WSAStartup(wVersionRequested: u16, lpWSAData: *mut WsaData) -> i32 {
    trace!("WSAStartup(0x{wVersionRequested:04x})");
    if lpWSAData.is_null() {
        set_wsa_last_error(WSAEFAULT);
        return SOCKET_ERROR;
    }

    unsafe {
        (*lpWSAData).wVersion = wVersionRequested;
        (*lpWSAData).wHighVersion = 0x0202;
        (*lpWSAData).iMaxSockets = 0;
        (*lpWSAData).iMaxUdpDg = 0;
        (*lpWSAData).lpVendorInfo = ptr::null_mut();
        ptr::write_bytes((*lpWSAData).szDescription.as_mut_ptr(), 0, 257);
        ptr::write_bytes((*lpWSAData).szSystemStatus.as_mut_ptr(), 0, 129);
    }
    set_wsa_last_error(0);
    0
}

pub extern "win64" fn WSACleanup() -> i32 {
    trace!("WSACleanup()");
    set_wsa_last_error(0);
    0
}

pub extern "win64" fn WSAGetLastError() -> i32 {
    WSA_LAST_ERROR.with(|cell| cell.get())
}

pub extern "win64" fn socket(af: i32, kind: i32, protocol: i32) -> usize {
    let fd = unsafe { libc::socket(af, kind, protocol) };
    if fd < 0 {
        set_wsa_error_from_errno();
        INVALID_SOCKET
    } else {
        set_wsa_last_error(0);
        fd as usize
    }
}

pub extern "win64" fn closesocket(s: usize) -> i32 {
    unregister_async_socket(s);
    let ret = unsafe { libc::close(s as c_int) };
    if ret == 0 {
        set_wsa_last_error(0);
        0
    } else {
        set_wsa_error_from_errno();
        SOCKET_ERROR
    }
}

pub extern "win64" fn connect(s: usize, name: *const libc::sockaddr, namelen: i32) -> i32 {
    let ret = unsafe { libc::connect(s as c_int, name, namelen as libc::socklen_t) };
    if ret == 0 {
        set_wsa_last_error(0);
        0
    } else {
        set_wsa_error_from_errno();
        SOCKET_ERROR
    }
}

pub extern "win64" fn bind(s: usize, name: *const libc::sockaddr, namelen: i32) -> i32 {
    let ret = unsafe { libc::bind(s as c_int, name, namelen as libc::socklen_t) };
    if ret == 0 {
        set_wsa_last_error(0);
        0
    } else {
        set_wsa_error_from_errno();
        SOCKET_ERROR
    }
}

pub extern "win64" fn listen(s: usize, backlog: i32) -> i32 {
    let ret = unsafe { libc::listen(s as c_int, backlog) };
    if ret == 0 {
        set_wsa_last_error(0);
        0
    } else {
        set_wsa_error_from_errno();
        SOCKET_ERROR
    }
}

pub extern "win64" fn accept(s: usize, addr: *mut libc::sockaddr, addrlen: *mut i32) -> usize {
    let mut len: libc::socklen_t =
        if addrlen.is_null() { 0 } else { unsafe { (*addrlen).max(0) as libc::socklen_t } };
    let fd = unsafe { libc::accept(s as c_int, addr, &raw mut len) };
    if fd < 0 {
        set_wsa_error_from_errno();
        INVALID_SOCKET
    } else {
        if !addrlen.is_null() {
            unsafe {
                *addrlen = len as i32;
            }
        }
        set_wsa_last_error(0);
        fd as usize
    }
}

pub extern "win64" fn send(s: usize, buf: *const c_char, len: i32, flags: i32) -> i32 {
    let ret = unsafe { libc::send(s as c_int, buf.cast::<c_void>(), len as usize, flags) };
    if ret < 0 {
        set_wsa_error_from_errno();
        SOCKET_ERROR
    } else {
        set_wsa_last_error(0);
        ret as i32
    }
}

pub extern "win64" fn recv(s: usize, buf: *mut c_char, len: i32, flags: i32) -> i32 {
    let ret = unsafe { libc::recv(s as c_int, buf.cast::<c_void>(), len as usize, flags) };
    if ret < 0 {
        set_wsa_error_from_errno();
        SOCKET_ERROR
    } else {
        set_wsa_last_error(0);
        ret as i32
    }
}

fn winfd_to_libc(ptr_set: *mut WinFdSet, out_max_fd: &mut c_int) -> Option<libc::fd_set> {
    if ptr_set.is_null() {
        return None;
    }

    let mut libc_set: libc::fd_set = unsafe { mem::zeroed() };
    unsafe {
        libc::FD_ZERO(&raw mut libc_set);
        let win_set = &*ptr_set;
        let count = usize::min(win_set.fd_count as usize, WINSOCK_FD_SETSIZE);
        for fd in win_set.fd_array.iter().take(count) {
            let fd_i = *fd as c_int;
            if fd_i > *out_max_fd {
                *out_max_fd = fd_i;
            }
            libc::FD_SET(fd_i, &raw mut libc_set);
        }
    }
    Some(libc_set)
}

fn libc_to_winfd(ptr_set: *mut WinFdSet, libc_set: &libc::fd_set) {
    if ptr_set.is_null() {
        return;
    }

    unsafe {
        let win_set = &mut *ptr_set;
        let mut count = 0usize;
        let input_count = usize::min(win_set.fd_count as usize, WINSOCK_FD_SETSIZE);
        let original = win_set.fd_array;
        for fd in original.iter().take(input_count) {
            let fd_i = *fd as c_int;
            if libc::FD_ISSET(fd_i, libc_set) && count < WINSOCK_FD_SETSIZE {
                win_set.fd_array[count] = *fd;
                count += 1;
            }
        }
        win_set.fd_count = count as u32;
        for idx in count..WINSOCK_FD_SETSIZE {
            win_set.fd_array[idx] = 0;
        }
    }
}

pub extern "win64" fn select(
    _nfds: i32,
    readfds: *mut WinFdSet,
    writefds: *mut WinFdSet,
    exceptfds: *mut WinFdSet,
    timeout: *mut WinTimeVal,
) -> i32 {
    let mut max_fd: c_int = -1;
    let mut read_libc = winfd_to_libc(readfds, &mut max_fd);
    let mut write_libc = winfd_to_libc(writefds, &mut max_fd);
    let mut except_libc = winfd_to_libc(exceptfds, &mut max_fd);

    let mut tv_native = libc::timeval { tv_sec: 0, tv_usec: 0 };
    let tv_ptr = if timeout.is_null() {
        ptr::null_mut()
    } else {
        unsafe {
            tv_native.tv_sec = (*timeout).tv_sec as libc::time_t;
            tv_native.tv_usec = (*timeout).tv_usec as libc::suseconds_t;
        }
        &raw mut tv_native
    };

    let ret = unsafe {
        libc::select(
            max_fd + 1,
            read_libc.as_mut().map_or(ptr::null_mut(), |set| set as *mut libc::fd_set),
            write_libc.as_mut().map_or(ptr::null_mut(), |set| set as *mut libc::fd_set),
            except_libc.as_mut().map_or(ptr::null_mut(), |set| set as *mut libc::fd_set),
            tv_ptr,
        )
    };

    if ret < 0 {
        set_wsa_error_from_errno();
        return SOCKET_ERROR;
    }

    if let Some(ref read_set) = read_libc {
        libc_to_winfd(readfds, read_set);
    }
    if let Some(ref write_set) = write_libc {
        libc_to_winfd(writefds, write_set);
    }
    if let Some(ref except_set) = except_libc {
        libc_to_winfd(exceptfds, except_set);
    }

    set_wsa_last_error(0);
    ret
}

pub extern "win64" fn getaddrinfo(
    node: *const c_char,
    service: *const c_char,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> i32 {
    let ret = unsafe { libc::getaddrinfo(node, service, hints, res) };
    if ret == 0 {
        set_wsa_last_error(0);
        return 0;
    }

    // getaddrinfo uses EAI_* return values, not errno.
    set_wsa_last_error(if ret == libc::EAI_NONAME { WSANO_DATA } else { WSAEINVAL });
    ret
}

pub extern "win64" fn freeaddrinfo(res: *mut libc::addrinfo) {
    unsafe {
        libc::freeaddrinfo(res);
    }
}

pub extern "win64" fn WSACreateEvent() -> Handle {
    init_global_table();
    let handle = nt_sync::create_event(true, false);
    if handle == INVALID_HANDLE_VALUE {
        set_wsa_last_error(WSAENOBUFS);
        return 0;
    }

    set_wsa_last_error(0);
    handle
}

pub extern "win64" fn WSACloseEvent(hEvent: Handle) -> i32 {
    init_global_table();
    if hEvent == 0 {
        set_wsa_last_error(WSAEINVAL);
        return 0;
    }

    if global_table().close_handle(hEvent) {
        set_wsa_last_error(0);
        1
    } else {
        set_wsa_last_error(WSAEINVAL);
        0
    }
}

pub extern "win64" fn WSASetEvent(hEvent: Handle) -> i32 {
    if nt_sync::set_event(hEvent) != 0 {
        set_wsa_last_error(0);
        1
    } else {
        set_wsa_last_error(WSAEINVAL);
        0
    }
}

pub extern "win64" fn WSAResetEvent(hEvent: Handle) -> i32 {
    if nt_sync::reset_event(hEvent) != 0 {
        set_wsa_last_error(0);
        1
    } else {
        set_wsa_last_error(WSAEINVAL);
        0
    }
}

pub extern "win64" fn WSAWaitForMultipleEvents(
    cEvents: u32,
    lphEvents: *const Handle,
    fWaitAll: i32,
    dwTimeout: u32,
    _fAlertable: i32,
) -> u32 {
    if cEvents == 0 {
        set_wsa_last_error(WSAEINVAL);
        return nt_sync::WAIT_FAILED;
    }
    if lphEvents.is_null() {
        set_wsa_last_error(WSAEFAULT);
        return nt_sync::WAIT_FAILED;
    }

    let handles = unsafe { std::slice::from_raw_parts(lphEvents, cEvents as usize) };
    let result = nt_sync::wait_for_multiple_objects(handles, fWaitAll != 0, dwTimeout);
    if result == nt_sync::WAIT_FAILED {
        set_wsa_last_error(WSAEINVAL);
    } else {
        set_wsa_last_error(0);
    }
    result
}

pub extern "win64" fn WSAAsyncSelect(s: usize, hWnd: usize, wMsg: u32, lEvent: i32) -> i32 {
    if lEvent == 0 {
        unregister_async_socket(s);
        set_wsa_last_error(0);
        return 0;
    }

    match register_async_socket(s, lEvent, AsyncNotifyMode::Message { hwnd: hWnd, msg: wMsg }) {
        Ok(()) => {
            set_wsa_last_error(0);
            0
        }
        Err(err) => {
            set_wsa_last_error(err);
            SOCKET_ERROR
        }
    }
}

pub extern "win64" fn WSAEventSelect(s: usize, hEventObject: Handle, lNetworkEvents: i32) -> i32 {
    if lNetworkEvents == 0 {
        unregister_async_socket(s);
        set_wsa_last_error(0);
        return 0;
    }

    if hEventObject == 0 {
        set_wsa_last_error(WSAEINVAL);
        return SOCKET_ERROR;
    }

    init_global_table();
    if !global_table().is_valid(hEventObject) {
        set_wsa_last_error(WSAEINVAL);
        return SOCKET_ERROR;
    }

    match register_async_socket(
        s,
        lNetworkEvents,
        AsyncNotifyMode::Event { event_handle: hEventObject },
    ) {
        Ok(()) => {
            set_wsa_last_error(0);
            0
        }
        Err(err) => {
            set_wsa_last_error(err);
            SOCKET_ERROR
        }
    }
}

unsafe fn build_iovecs(
    lpBuffers: *const WsaBuf,
    dwBufferCount: u32,
) -> Result<Vec<libc::iovec>, i32> {
    if lpBuffers.is_null() {
        return Err(WSAEFAULT);
    }

    let buffers = std::slice::from_raw_parts(lpBuffers, dwBufferCount as usize);
    let mut iovecs = Vec::with_capacity(buffers.len());
    for buffer in buffers {
        if buffer.len > 0 && buffer.buf.is_null() {
            return Err(WSAEFAULT);
        }

        iovecs.push(libc::iovec {
            iov_base: buffer.buf.cast::<c_void>(),
            iov_len: buffer.len as usize,
        });
    }

    Ok(iovecs)
}

fn send_wsabufs(
    s: usize,
    lpBuffers: *const WsaBuf,
    dwBufferCount: u32,
    dwFlags: u32,
) -> Result<u32, i32> {
    let mut iovecs = unsafe { build_iovecs(lpBuffers, dwBufferCount)? };

    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = iovecs.as_mut_ptr();
    msg.msg_iovlen = iovecs.len();

    let ret = unsafe { libc::sendmsg(s as c_int, &msg, dwFlags as c_int) };
    if ret < 0 {
        Err(map_errno_to_wsa(last_errno()))
    } else {
        Ok(ret as u32)
    }
}

fn recv_wsabufs(
    s: usize,
    lpBuffers: *mut WsaBuf,
    dwBufferCount: u32,
    dwFlags: u32,
    out_flags: *mut u32,
) -> Result<u32, i32> {
    let mut iovecs = unsafe { build_iovecs(lpBuffers.cast::<WsaBuf>(), dwBufferCount)? };

    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = iovecs.as_mut_ptr();
    msg.msg_iovlen = iovecs.len();

    let ret = unsafe { libc::recvmsg(s as c_int, &raw mut msg, dwFlags as c_int) };
    if ret < 0 {
        Err(map_errno_to_wsa(last_errno()))
    } else {
        if !out_flags.is_null() {
            unsafe {
                *out_flags = msg.msg_flags as u32;
            }
        }
        Ok(ret as u32)
    }
}

unsafe fn mark_overlapped_pending(lpOverlapped: *mut WsaOverlapped) {
    if lpOverlapped.is_null() {
        return;
    }
    (*lpOverlapped).Internal = WSA_IO_PENDING as usize;
    (*lpOverlapped).InternalHigh = 0;
}

unsafe fn complete_overlapped(lpOverlapped: *mut WsaOverlapped, error: i32, transferred: u32) {
    if lpOverlapped.is_null() {
        return;
    }

    (*lpOverlapped).Internal = if error == 0 { 0 } else { error as usize };
    (*lpOverlapped).InternalHigh = transferred as usize;

    if (*lpOverlapped).hEvent != 0 {
        let _ = nt_sync::set_event((*lpOverlapped).hEvent);
    }
}

unsafe fn invoke_completion_routine(
    completion: Option<WsaOverlappedCompletionRoutine>,
    error: i32,
    transferred: u32,
    lpOverlapped: *mut WsaOverlapped,
    flags: u32,
) {
    if let Some(callback) = completion {
        callback(error as u32, transferred, lpOverlapped, flags);
    }
}

pub extern "win64" fn WSASend(
    s: usize,
    lpBuffers: *const WsaBuf,
    dwBufferCount: u32,
    lpNumberOfBytesSent: *mut u32,
    dwFlags: u32,
    lpOverlapped: *mut WsaOverlapped,
    lpCompletionRoutine: Option<WsaOverlappedCompletionRoutine>,
) -> i32 {
    if lpBuffers.is_null() || dwBufferCount == 0 {
        set_wsa_last_error(WSAEFAULT);
        return SOCKET_ERROR;
    }

    if lpOverlapped.is_null() {
        match send_wsabufs(s, lpBuffers, dwBufferCount, dwFlags) {
            Ok(bytes_sent) => {
                if !lpNumberOfBytesSent.is_null() {
                    unsafe {
                        *lpNumberOfBytesSent = bytes_sent;
                    }
                }
                set_wsa_last_error(0);
                0
            }
            Err(err) => {
                set_wsa_last_error(err);
                SOCKET_ERROR
            }
        }
    } else {
        if let Err(err) = set_socket_nonblocking(s, true) {
            set_wsa_last_error(err);
            return SOCKET_ERROR;
        }

        match send_wsabufs(s, lpBuffers, dwBufferCount, dwFlags) {
            Ok(bytes_sent) => {
                unsafe {
                    complete_overlapped(lpOverlapped, 0, bytes_sent);
                    invoke_completion_routine(lpCompletionRoutine, 0, bytes_sent, lpOverlapped, 0);
                }
                if !lpNumberOfBytesSent.is_null() {
                    unsafe {
                        *lpNumberOfBytesSent = bytes_sent;
                    }
                }
                set_wsa_last_error(0);
                0
            }
            Err(err) if is_would_block(err) => {
                unsafe {
                    mark_overlapped_pending(lpOverlapped);
                }

                let socket = s;
                let buffers_addr = lpBuffers as usize;
                let overlapped_addr = lpOverlapped as usize;

                std::thread::spawn(move || {
                    let mut completion_error = 0;
                    let mut bytes_sent = 0;

                    loop {
                        match send_wsabufs(
                            socket,
                            buffers_addr as *const WsaBuf,
                            dwBufferCount,
                            dwFlags,
                        ) {
                            Ok(sent) => {
                                bytes_sent = sent;
                                break;
                            }
                            Err(next_err) if is_would_block(next_err) => {
                                match wait_socket_epoll(
                                    socket,
                                    (libc::EPOLLOUT as u32) | (libc::EPOLLERR as u32),
                                    OVERLAPPED_WAIT_TIMEOUT_MS,
                                ) {
                                    Ok(()) => continue,
                                    Err(wait_err) => {
                                        completion_error = wait_err;
                                        break;
                                    }
                                }
                            }
                            Err(next_err) => {
                                completion_error = next_err;
                                break;
                            }
                        }
                    }

                    unsafe {
                        complete_overlapped(
                            overlapped_addr as *mut WsaOverlapped,
                            completion_error,
                            bytes_sent,
                        );
                        invoke_completion_routine(
                            lpCompletionRoutine,
                            completion_error,
                            bytes_sent,
                            overlapped_addr as *mut WsaOverlapped,
                            0,
                        );
                    }
                });

                set_wsa_last_error(WSA_IO_PENDING);
                SOCKET_ERROR
            }
            Err(err) => {
                set_wsa_last_error(err);
                SOCKET_ERROR
            }
        }
    }
}

pub extern "win64" fn WSARecv(
    s: usize,
    lpBuffers: *mut WsaBuf,
    dwBufferCount: u32,
    lpNumberOfBytesRecvd: *mut u32,
    lpFlags: *mut u32,
    lpOverlapped: *mut WsaOverlapped,
    lpCompletionRoutine: Option<WsaOverlappedCompletionRoutine>,
) -> i32 {
    if lpBuffers.is_null() || dwBufferCount == 0 {
        set_wsa_last_error(WSAEFAULT);
        return SOCKET_ERROR;
    }

    let flags = if lpFlags.is_null() { 0 } else { unsafe { *lpFlags } };

    if lpOverlapped.is_null() {
        match recv_wsabufs(s, lpBuffers, dwBufferCount, flags, lpFlags) {
            Ok(bytes_recvd) => {
                if !lpNumberOfBytesRecvd.is_null() {
                    unsafe {
                        *lpNumberOfBytesRecvd = bytes_recvd;
                    }
                }
                set_wsa_last_error(0);
                0
            }
            Err(err) => {
                set_wsa_last_error(err);
                SOCKET_ERROR
            }
        }
    } else {
        if let Err(err) = set_socket_nonblocking(s, true) {
            set_wsa_last_error(err);
            return SOCKET_ERROR;
        }

        match recv_wsabufs(s, lpBuffers, dwBufferCount, flags, lpFlags) {
            Ok(bytes_recvd) => {
                unsafe {
                    complete_overlapped(lpOverlapped, 0, bytes_recvd);
                    invoke_completion_routine(
                        lpCompletionRoutine,
                        0,
                        bytes_recvd,
                        lpOverlapped,
                        if lpFlags.is_null() { 0 } else { *lpFlags },
                    );
                }
                if !lpNumberOfBytesRecvd.is_null() {
                    unsafe {
                        *lpNumberOfBytesRecvd = bytes_recvd;
                    }
                }
                set_wsa_last_error(0);
                0
            }
            Err(err) if is_would_block(err) => {
                unsafe {
                    mark_overlapped_pending(lpOverlapped);
                }

                let socket = s;
                let buffers_addr = lpBuffers as usize;
                let overlapped_addr = lpOverlapped as usize;

                std::thread::spawn(move || {
                    let mut completion_error = 0;
                    let mut bytes_recvd = 0;
                    let mut completion_flags = 0;

                    loop {
                        match recv_wsabufs(
                            socket,
                            buffers_addr as *mut WsaBuf,
                            dwBufferCount,
                            flags,
                            &raw mut completion_flags,
                        ) {
                            Ok(recvd) => {
                                bytes_recvd = recvd;
                                break;
                            }
                            Err(next_err) if is_would_block(next_err) => {
                                match wait_socket_epoll(
                                    socket,
                                    (libc::EPOLLIN as u32) | (libc::EPOLLERR as u32),
                                    OVERLAPPED_WAIT_TIMEOUT_MS,
                                ) {
                                    Ok(()) => continue,
                                    Err(wait_err) => {
                                        completion_error = wait_err;
                                        break;
                                    }
                                }
                            }
                            Err(next_err) => {
                                completion_error = next_err;
                                break;
                            }
                        }
                    }

                    unsafe {
                        complete_overlapped(
                            overlapped_addr as *mut WsaOverlapped,
                            completion_error,
                            bytes_recvd,
                        );
                        invoke_completion_routine(
                            lpCompletionRoutine,
                            completion_error,
                            bytes_recvd,
                            overlapped_addr as *mut WsaOverlapped,
                            completion_flags,
                        );
                    }
                });

                set_wsa_last_error(WSA_IO_PENDING);
                SOCKET_ERROR
            }
            Err(err) => {
                set_wsa_last_error(err);
                SOCKET_ERROR
            }
        }
    }
}

pub extern "win64" fn WSAGetOverlappedResult(
    _s: usize,
    lpOverlapped: *mut WsaOverlapped,
    lpcbTransfer: *mut u32,
    fWait: i32,
    lpdwFlags: *mut u32,
) -> i32 {
    if lpOverlapped.is_null() || lpcbTransfer.is_null() {
        set_wsa_last_error(WSAEFAULT);
        return 0;
    }

    let mut internal = unsafe { (*lpOverlapped).Internal };
    if internal == WSA_IO_PENDING as usize && fWait != 0 {
        let event = unsafe { (*lpOverlapped).hEvent };
        if event != 0 {
            let result = nt_sync::wait_for_single_object(event, nt_sync::INFINITE);
            if result != nt_sync::WAIT_OBJECT_0 {
                set_wsa_last_error(WSAEINVAL);
                return 0;
            }
        } else {
            loop {
                let pending = unsafe { (*lpOverlapped).Internal } == WSA_IO_PENDING as usize;
                if !pending {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        internal = unsafe { (*lpOverlapped).Internal };
    }

    if internal == WSA_IO_PENDING as usize {
        set_wsa_last_error(WSA_IO_INCOMPLETE);
        return 0;
    }

    if internal != 0 {
        set_wsa_last_error(internal as i32);
        return 0;
    }

    unsafe {
        *lpcbTransfer = (*lpOverlapped).InternalHigh as u32;
        if !lpdwFlags.is_null() {
            *lpdwFlags = 0;
        }
    }

    set_wsa_last_error(0);
    1
}

pub fn set_async_select_callback(callback: Option<AsyncSelectCallback>) {
    if let Ok(runtime) = get_or_init_async_runtime() {
        *runtime.callback.write().expect("async callback lock poisoned") = callback;
    }
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();

    exports.insert("WSAStartup", WSAStartup as usize);
    exports.insert("WSACleanup", WSACleanup as usize);
    exports.insert("WSAGetLastError", WSAGetLastError as usize);
    exports.insert("WSAAsyncSelect", WSAAsyncSelect as usize);
    exports.insert("WSAEventSelect", WSAEventSelect as usize);
    exports.insert("WSACreateEvent", WSACreateEvent as usize);
    exports.insert("WSACloseEvent", WSACloseEvent as usize);
    exports.insert("WSASetEvent", WSASetEvent as usize);
    exports.insert("WSAResetEvent", WSAResetEvent as usize);
    exports.insert("WSAWaitForMultipleEvents", WSAWaitForMultipleEvents as usize);
    exports.insert("WSASend", WSASend as usize);
    exports.insert("WSARecv", WSARecv as usize);
    exports.insert("WSAGetOverlappedResult", WSAGetOverlappedResult as usize);
    exports.insert("socket", socket as usize);
    exports.insert("closesocket", closesocket as usize);
    exports.insert("connect", connect as usize);
    exports.insert("bind", bind as usize);
    exports.insert("listen", listen as usize);
    exports.insert("accept", accept as usize);
    exports.insert("send", send as usize);
    exports.insert("recv", recv as usize);
    exports.insert("select", select as usize);
    exports.insert("getaddrinfo", getaddrinfo as usize);
    exports.insert("freeaddrinfo", freeaddrinfo as usize);

    exports
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;
    use std::sync::{Mutex, OnceLock};

    #[derive(Debug, Default, Clone, Copy)]
    struct AsyncObservation {
        hwnd: usize,
        msg: u32,
        socket: usize,
        events: i32,
        error: i32,
        count: u32,
    }

    fn async_observation() -> &'static Mutex<AsyncObservation> {
        static OBS: OnceLock<Mutex<AsyncObservation>> = OnceLock::new();
        OBS.get_or_init(|| Mutex::new(AsyncObservation::default()))
    }

    extern "C" fn test_async_callback(
        hwnd: usize,
        msg: u32,
        socket: usize,
        events: i32,
        error: i32,
    ) {
        let mut guard = async_observation().lock().expect("async observation poisoned");
        guard.hwnd = hwnd;
        guard.msg = msg;
        guard.socket = socket;
        guard.events = events;
        guard.error = error;
        guard.count = guard.count.saturating_add(1);
    }

    fn send_with_retry(fd: c_int, payload: &[u8]) -> isize {
        for _ in 0..100 {
            let sent = unsafe { libc::write(fd, payload.as_ptr().cast::<c_void>(), payload.len()) };
            if sent >= 0 {
                return sent;
            }

            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno == libc::EINTR || errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
            return sent;
        }

        -1
    }

    #[test]
    fn startup_and_cleanup_succeed() {
        let _guard = crate::test_support::serial_guard();
        let mut data = WsaData {
            wVersion: 0,
            wHighVersion: 0,
            iMaxSockets: 0,
            iMaxUdpDg: 0,
            lpVendorInfo: ptr::null_mut(),
            szDescription: [0; 257],
            szSystemStatus: [0; 129],
        };
        assert_eq!(WSAStartup(0x0202, &raw mut data), 0);
        assert_eq!(WSACleanup(), 0);
    }

    #[test]
    fn socket_and_close_round_trip() {
        let _guard = crate::test_support::serial_guard();
        let s = socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if s == INVALID_SOCKET {
            assert_ne!(WSAGetLastError(), 0);
        } else {
            assert_eq!(closesocket(s), 0);
        }
    }

    #[test]
    fn getaddrinfo_localhost_succeeds() {
        let _guard = crate::test_support::serial_guard();
        let host = CStr::from_bytes_with_nul(b"localhost\0").expect("cstr");
        let mut res: *mut libc::addrinfo = ptr::null_mut();
        let ret = getaddrinfo(host.as_ptr(), ptr::null(), ptr::null(), &raw mut res);
        assert_eq!(ret, 0);
        assert!(!res.is_null());
        freeaddrinfo(res);
    }

    #[test]
    fn async_select_callback_fires_for_readable_socket() {
        let _guard = crate::test_support::serial_guard();
        set_async_select_callback(Some(test_async_callback));
        {
            let mut state = async_observation().lock().expect("async observation poisoned");
            *state = AsyncObservation::default();
        }

        let mut pair = [0_i32; 2];
        let ret =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) };
        assert_eq!(ret, 0);

        let client = pair[0] as usize;
        let peer = pair[1] as usize;

        assert_eq!(WSAAsyncSelect(client, 0x1234, 0x3344, FD_READ | FD_CLOSE), 0);
        let payload = b"x";
        let sent = send_with_retry(peer as c_int, payload);
        assert_eq!(sent, payload.len() as isize);

        let mut seen = false;
        for _ in 0..100 {
            let state = *async_observation().lock().expect("async observation poisoned");
            if state.count > 0 {
                assert_eq!(state.hwnd, 0x1234);
                assert_eq!(state.msg, 0x3344);
                assert_eq!(state.socket, client);
                assert_eq!(state.error, 0);
                assert!(state.events & FD_READ != 0);
                seen = true;
                break;
            }

            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        assert!(seen, "expected async callback to fire");
        assert_eq!(WSAAsyncSelect(client, 0, 0, 0), 0);
        assert_eq!(closesocket(client), 0);
        assert_eq!(closesocket(peer), 0);
        set_async_select_callback(None);
    }

    #[test]
    fn overlapped_recv_completes_with_event_signal() {
        let _guard = crate::test_support::serial_guard();

        let mut pair = [0_i32; 2];
        let ret =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) };
        assert_eq!(ret, 0);

        let receiver = pair[0] as usize;
        let sender = pair[1] as usize;

        let event = WSACreateEvent();
        assert_ne!(event, 0);

        let mut recv_buffer = [0_i8; 32];
        let mut wsabuf = WsaBuf { len: recv_buffer.len() as u32, buf: recv_buffer.as_mut_ptr() };
        let mut bytes_recvd: u32 = 0;
        let mut flags: u32 = 0;
        let mut overlapped =
            WsaOverlapped { Internal: 0, InternalHigh: 0, Offset: 0, OffsetHigh: 0, hEvent: event };

        let recv_result = WSARecv(
            receiver,
            &raw mut wsabuf,
            1,
            &raw mut bytes_recvd,
            &raw mut flags,
            &raw mut overlapped,
            None,
        );
        if recv_result == SOCKET_ERROR {
            assert_eq!(WSAGetLastError(), WSA_IO_PENDING);
        }

        let payload = b"ping";
        let sent = send_with_retry(sender as c_int, payload);
        assert_eq!(sent, payload.len() as isize);

        if recv_result == SOCKET_ERROR {
            let wait_result = WSAWaitForMultipleEvents(1, &raw const event, 0, 1000, 0);
            assert_eq!(wait_result, nt_sync::WAIT_OBJECT_0);
        }

        let mut transferred = 0_u32;
        assert_eq!(
            WSAGetOverlappedResult(
                receiver,
                &raw mut overlapped,
                &raw mut transferred,
                1,
                &raw mut flags,
            ),
            1
        );
        assert_eq!(transferred as usize, payload.len());
        assert_eq!(
            unsafe { std::slice::from_raw_parts(recv_buffer.as_ptr().cast::<u8>(), payload.len()) },
            payload
        );

        assert_eq!(WSACloseEvent(event), 1);
        assert_eq!(closesocket(receiver), 0);
        assert_eq!(closesocket(sender), 0);
    }
}
