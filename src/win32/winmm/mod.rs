#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! WinMM timers and a small `waveOut` implementation.
//!
//! PulseAudio's simple API is also provided by PipeWire's PulseAudio server,
//! so dynamically loading it gives us a real desktop-audio backend without a
//! link-time dependency on either development package.  Guest audio buffers
//! are copied before being handed to the host worker; this is important as a
//! game is allowed to reuse a `WAVEHDR` as soon as it is marked done.

use std::{
    collections::HashMap,
    ffi::{c_char, c_void, CString},
    ptr,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, Sender},
        Arc, OnceLock, RwLock,
    },
    time::Duration,
};
use tracing::{debug, trace, warn};

const MMSYSERR_NOERROR: u32 = 0;
const MMSYSERR_ERROR: u32 = 1;
const MMSYSERR_BADDEVICEID: u32 = 2;
const MMSYSERR_NODRIVER: u32 = 6;
const MMSYSERR_NOMEM: u32 = 7;
const MMSYSERR_INVALHANDLE: u32 = 5;
const MMSYSERR_INVALPARAM: u32 = 11;
const WAVERR_BADFORMAT: u32 = 32;
const WAVERR_STILLPLAYING: u32 = 33;
const WAVERR_UNPREPARED: u32 = 34;

const WAVE_MAPPER: u32 = u32::MAX;
const WAVE_FORMAT_QUERY: u32 = 0x0001;
const CALLBACK_TYPEMASK: u32 = 0x0007_0000;
const CALLBACK_EVENT: u32 = 0x0005_0000;
const WHDR_DONE: u32 = 0x0000_0001;
const WHDR_PREPARED: u32 = 0x0000_0002;
const WHDR_INQUEUE: u32 = 0x0000_0010;
const TIME_MS: u32 = 1;
const TIME_SAMPLES: u32 = 2;
const TIME_BYTES: u32 = 4;

const WAVE_FORMAT_PCM: u16 = 1;
const WAVE_FORMAT_IEEE_FLOAT: u16 = 3;
const WAVE_FORMAT_EXTENSIBLE: u16 = 0xfffe;

// Values of `pa_sample_format_t` on a little-endian host.  These are a stable
// part of libpulse's ABI and avoid requiring pulse headers at build time.
const PA_SAMPLE_U8: u32 = 0;
const PA_SAMPLE_S16LE: u32 = 3;
const PA_SAMPLE_FLOAT32LE: u32 = 5;
const PA_STREAM_PLAYBACK: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct PaSampleSpec {
    format: u32,
    rate: u32,
    channels: u8,
    _padding: [u8; 3],
}

type PaSimpleNew = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    u32,
    *const c_char,
    *const c_char,
    *const PaSampleSpec,
    *const c_void,
    *const c_void,
    *mut i32,
) -> *mut c_void;
type PaSimpleWrite = unsafe extern "C" fn(*mut c_void, *const c_void, usize, *mut i32) -> i32;
type PaSimpleFree = unsafe extern "C" fn(*mut c_void);

#[derive(Clone, Copy)]
struct PulseApi {
    new: PaSimpleNew,
    write: PaSimpleWrite,
    free: PaSimpleFree,
}

// The loaded library deliberately remains resident until process exit, and
// function pointers are immutable C entry points.
unsafe impl Send for PulseApi {}
unsafe impl Sync for PulseApi {}

unsafe fn pulse_symbol(handle: *mut c_void, name: &[u8]) -> Option<*mut c_void> {
    let symbol = unsafe { libc::dlsym(handle, name.as_ptr().cast()) };
    (!symbol.is_null()).then_some(symbol)
}

fn load_pulse_api() -> Option<PulseApi> {
    static API: OnceLock<Option<PulseApi>> = OnceLock::new();
    *API.get_or_init(|| unsafe {
        let mut handle = ptr::null_mut();
        for library in [b"libpulse-simple.so.0\0".as_slice(), b"libpulse-simple.so\0".as_slice()] {
            handle = libc::dlopen(library.as_ptr().cast(), libc::RTLD_NOW | libc::RTLD_LOCAL);
            if !handle.is_null() {
                break;
            }
        }
        if handle.is_null() {
            debug!("libpulse-simple is unavailable; waveOut has no host backend");
            return None;
        }
        let new = pulse_symbol(handle, b"pa_simple_new\0")?;
        let write = pulse_symbol(handle, b"pa_simple_write\0")?;
        let free = pulse_symbol(handle, b"pa_simple_free\0")?;
        Some(PulseApi {
            new: std::mem::transmute::<*mut c_void, PaSimpleNew>(new),
            write: std::mem::transmute::<*mut c_void, PaSimpleWrite>(write),
            free: std::mem::transmute::<*mut c_void, PaSimpleFree>(free),
        })
    })
}

struct PulseStream {
    stream: *mut c_void,
    api: PulseApi,
}

unsafe impl Send for PulseStream {}

impl PulseStream {
    fn open(format: WaveFormat) -> Option<Self> {
        let api = load_pulse_api()?;
        let app_name = CString::new("TuxExe-rs").expect("static string has no NUL");
        let stream_name = CString::new("Windows waveOut").expect("static string has no NUL");
        let spec = PaSampleSpec {
            format: format.pulse_format,
            rate: format.rate,
            channels: format.channels,
            _padding: [0; 3],
        };
        let mut error = 0;
        let stream = unsafe {
            (api.new)(
                ptr::null(),
                app_name.as_ptr(),
                PA_STREAM_PLAYBACK,
                ptr::null(),
                stream_name.as_ptr(),
                &spec,
                ptr::null(),
                ptr::null(),
                &mut error,
            )
        };
        if stream.is_null() {
            debug!(error, "pa_simple_new failed");
            None
        } else {
            Some(Self { stream, api })
        }
    }

    fn write(&mut self, bytes: &[u8]) -> bool {
        let mut error = 0;
        let status = unsafe {
            (self.api.write)(self.stream, bytes.as_ptr().cast(), bytes.len(), &mut error)
        };
        if status < 0 {
            warn!(error, "pa_simple_write failed; dropping waveOut buffer");
            false
        } else {
            true
        }
    }
}

impl Drop for PulseStream {
    fn drop(&mut self) {
        unsafe { (self.api.free)(self.stream) };
    }
}

/// Minimal playback sink shared with the DirectSound facade.  Keeping the
/// Pulse loader in WinMM means DirectSound and waveOut select the exact same
/// PipeWire-Pulse/PulseAudio endpoint and avoids a second dynamic ABI shim.
pub(crate) struct DesktopAudioStream(PulseStream);

impl DesktopAudioStream {
    /// Opens a host playback stream for the PCM formats DirectSound games
    /// commonly submit. Unsupported formats deliberately fail here, so the
    /// caller can return `DSERR_BADFORMAT` instead of claiming a device that
    /// will silently consume corrupt samples.
    pub(crate) fn open(format_tag: u16, channels: u16, rate: u32, bits: u16) -> Option<Self> {
        if channels == 0 || channels > 32 || rate == 0 {
            return None;
        }
        let pulse_format = match (format_tag, bits) {
            (WAVE_FORMAT_PCM, 8) => PA_SAMPLE_U8,
            (WAVE_FORMAT_PCM, 16) => PA_SAMPLE_S16LE,
            (WAVE_FORMAT_IEEE_FLOAT, 32) => PA_SAMPLE_FLOAT32LE,
            _ => return None,
        };
        let bytes_per_sample = u32::from(bits / 8);
        let block_align = u32::from(channels).checked_mul(bytes_per_sample)?;
        Some(Self(PulseStream::open(WaveFormat {
            pulse_format,
            rate,
            channels: channels as u8,
            average_bytes_per_second: rate.checked_mul(block_align)?,
            block_align: block_align as u16,
        })?))
    }

    pub(crate) fn write(&mut self, bytes: &[u8]) -> bool {
        self.0.write(bytes)
    }
}

#[derive(Clone, Copy, Debug)]
struct WaveFormat {
    pulse_format: u32,
    rate: u32,
    channels: u8,
    average_bytes_per_second: u32,
    block_align: u16,
}

/// Read the Win64 `WAVEFORMATEX`/`WAVEFORMATEXTENSIBLE` layout without
/// imposing Rust alignment requirements on guest memory.
unsafe fn parse_wave_format(ptr: *const u8) -> Option<WaveFormat> {
    if ptr.is_null() {
        return None;
    }
    let tag = unsafe { ptr.cast::<u16>().read_unaligned() };
    let channels = unsafe { ptr.add(2).cast::<u16>().read_unaligned() };
    let rate = unsafe { ptr.add(4).cast::<u32>().read_unaligned() };
    let average_bytes_per_second = unsafe { ptr.add(8).cast::<u32>().read_unaligned() };
    let block_align = unsafe { ptr.add(12).cast::<u16>().read_unaligned() };
    let bits = unsafe { ptr.add(14).cast::<u16>().read_unaligned() };
    let extension_size = unsafe { ptr.add(16).cast::<u16>().read_unaligned() };
    if channels == 0 || channels > 32 || rate == 0 || block_align == 0 {
        return None;
    }

    let canonical_tag = if tag == WAVE_FORMAT_EXTENSIBLE {
        // WAVEFORMATEXTENSIBLE has a 22 byte extension; its SubFormat GUID's
        // Data1 is the base format tag for the PCM and float GUIDs.
        if extension_size < 22 {
            return None;
        }
        unsafe { ptr.add(24).cast::<u32>().read_unaligned() as u16 }
    } else {
        tag
    };
    let pulse_format = match (canonical_tag, bits) {
        (WAVE_FORMAT_PCM, 8) => PA_SAMPLE_U8,
        (WAVE_FORMAT_PCM, 16) => PA_SAMPLE_S16LE,
        (WAVE_FORMAT_IEEE_FLOAT, 32) => PA_SAMPLE_FLOAT32LE,
        _ => return None,
    };
    Some(WaveFormat {
        pulse_format,
        rate,
        channels: channels as u8,
        average_bytes_per_second,
        block_align,
    })
}

// WAVEHDR is 48 bytes in the Win64 ABI.  Fields are accessed by offset so a
// guest can pass naturally aligned Windows memory on either host alignment.
const WAVEHDR_SIZE: u32 = 48;
const WAVEHDR_DATA: usize = 0;
const WAVEHDR_LENGTH: usize = 8;
const WAVEHDR_FLAGS: usize = 24;

unsafe fn header_flags(header: usize) -> u32 {
    unsafe { (header + WAVEHDR_FLAGS) as *const u32 }.read_unaligned()
}

unsafe fn set_header_flags(header: usize, flags: u32) {
    unsafe { ((header + WAVEHDR_FLAGS) as *mut u32).write_unaligned(flags) };
}

unsafe fn complete_header(header: usize) {
    let flags = unsafe { header_flags(header) };
    unsafe { set_header_flags(header, (flags | WHDR_DONE) & !WHDR_INQUEUE) };
}

fn signal_completion(event: usize) {
    if event != 0 {
        // CALLBACK_EVENT is explicitly designed to be signalled by the audio
        // worker. It does not enter guest code, unlike CALLBACK_FUNCTION.
        crate::win32::kernel32::sync::SetEvent(event);
    }
}

enum WaveCommand {
    Buffer { header: usize, data: Vec<u8>, event: usize },
    Reset { complete: Sender<()> },
    Shutdown { complete: Sender<()> },
}

struct WaveOutDevice {
    sender: Sender<WaveCommand>,
    format: WaveFormat,
    pending: Arc<AtomicUsize>,
    completed_bytes: Arc<AtomicU64>,
    worker: Option<std::thread::JoinHandle<()>>,
}

fn devices() -> &'static RwLock<HashMap<usize, WaveOutDevice>> {
    static DEVICES: OnceLock<RwLock<HashMap<usize, WaveOutDevice>>> = OnceLock::new();
    DEVICES.get_or_init(|| RwLock::new(HashMap::new()))
}

fn next_wave_handle() -> usize {
    static NEXT_HANDLE: AtomicUsize = AtomicUsize::new(0xA110_0000);
    NEXT_HANDLE.fetch_add(1, Ordering::Relaxed)
}

fn start_wave_device(
    format: WaveFormat,
    callback: usize,
    flags: u32,
) -> Result<WaveOutDevice, u32> {
    let (sender, receiver) = mpsc::channel();
    let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
    let pending = Arc::new(AtomicUsize::new(0));
    let completed_bytes = Arc::new(AtomicU64::new(0));
    let worker_pending = Arc::clone(&pending);
    let worker_completed = Arc::clone(&completed_bytes);
    let event = ((flags & CALLBACK_TYPEMASK) == CALLBACK_EVENT).then_some(callback).unwrap_or(0);
    let worker = std::thread::Builder::new()
        .name("tuxexe-waveout".into())
        .spawn(move || {
            wave_worker(receiver, format, event, worker_pending, worker_completed, ready_sender)
        })
        .map_err(|_| MMSYSERR_NOMEM)?;

    match ready_receiver.recv_timeout(Duration::from_secs(2)) {
        Ok(true) => {
            Ok(WaveOutDevice { sender, format, pending, completed_bytes, worker: Some(worker) })
        }
        Ok(false) => {
            let _ = worker.join();
            Err(MMSYSERR_NODRIVER)
        }
        Err(_) => {
            // An inaccessible audio server should not hold game startup
            // indefinitely. The worker owns no guest pointers before a write.
            Err(MMSYSERR_NODRIVER)
        }
    }
}

fn wave_worker(
    receiver: mpsc::Receiver<WaveCommand>,
    format: WaveFormat,
    event: usize,
    pending: Arc<AtomicUsize>,
    completed_bytes: Arc<AtomicU64>,
    ready: mpsc::SyncSender<bool>,
) {
    let Some(mut stream) = PulseStream::open(format) else {
        let _ = ready.send(false);
        return;
    };
    let _ = ready.send(true);
    while let Ok(command) = receiver.recv() {
        match command {
            WaveCommand::Buffer { header, data, event: buffer_event } => {
                let _ = stream.write(&data);
                completed_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                pending.fetch_sub(1, Ordering::Release);
                unsafe { complete_header(header) };
                signal_completion(buffer_event.max(event));
            }
            WaveCommand::Reset { complete } => {
                // Commands already received are serialized by this worker, so
                // all earlier headers have been completed at this point.
                let _ = complete.send(());
            }
            WaveCommand::Shutdown { complete } => {
                let _ = complete.send(());
                break;
            }
        }
    }
}

fn with_device<R>(handle: usize, f: impl FnOnce(&WaveOutDevice) -> R) -> Option<R> {
    let devices = devices().read().expect("waveOut device registry poisoned");
    devices.get(&handle).map(f)
}

extern "win64" fn timeGetTime() -> u32 {
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    (ts.as_millis() & 0xFFFF_FFFF) as u32
}

extern "win64" fn timeBeginPeriod(_uPeriod: u32) -> u32 {
    MMSYSERR_NOERROR
}
extern "win64" fn timeEndPeriod(_uPeriod: u32) -> u32 {
    MMSYSERR_NOERROR
}

extern "win64" fn timeGetDevCaps(caps: *mut u8, size: u32) -> u32 {
    if caps.is_null() || size < 8 {
        return MMSYSERR_INVALPARAM;
    }
    unsafe {
        caps.cast::<u32>().write_unaligned(1);
        caps.add(4).cast::<u32>().write_unaligned(1);
    }
    MMSYSERR_NOERROR
}

/// Host-created threads cannot safely enter a PE callback without guest TEB/TLS.
extern "win64" fn timeSetEvent(
    _delay: u32,
    _resolution: u32,
    _callback: usize,
    _user: usize,
    _event_type: u32,
) -> u32 {
    0
}
extern "win64" fn timeKillEvent(_timer_id: u32) -> u32 {
    MMSYSERR_NOERROR
}

extern "win64" fn waveOutGetNumDevs() -> u32 {
    u32::from(load_pulse_api().is_some())
}

fn write_wave_out_caps(caps: *mut u8, size: u32, wide: bool) -> u32 {
    if caps.is_null() {
        return MMSYSERR_INVALPARAM;
    }
    let expected = if wide { 84 } else { 52 };
    if size < expected {
        return MMSYSERR_INVALPARAM;
    }
    unsafe {
        ptr::write_bytes(caps, 0, expected as usize);
        caps.cast::<u16>().write_unaligned(1); // Microsoft manufacturer id
        caps.add(2).cast::<u16>().write_unaligned(1);
        caps.add(4).cast::<u32>().write_unaligned(1);
        let name = if wide {
            b"TuxExe PulseAudio\0".as_slice()
        } else {
            b"TuxExe PulseAudio\0".as_slice()
        };
        if wide {
            for (index, byte) in name.iter().enumerate() {
                caps.add(8 + index * 2).cast::<u16>().write_unaligned(*byte as u16);
            }
        } else {
            ptr::copy_nonoverlapping(name.as_ptr(), caps.add(8), name.len());
        }
        let format_offset = if wide { 72 } else { 40 };
        caps.add(format_offset).cast::<u32>().write_unaligned(0x0000_0fff);
        caps.add(format_offset + 4).cast::<u16>().write_unaligned(2);
    }
    MMSYSERR_NOERROR
}

extern "win64" fn waveOutGetDevCapsW(_uDeviceID: usize, caps: *mut u8, size: u32) -> u32 {
    write_wave_out_caps(caps, size, true)
}
extern "win64" fn waveOutGetDevCapsA(_uDeviceID: usize, caps: *mut u8, size: u32) -> u32 {
    write_wave_out_caps(caps, size, false)
}

extern "win64" fn waveOutOpen(
    phwo: *mut usize,
    device_id: u32,
    pwfx: *const u8,
    callback: usize,
    instance: usize,
    flags: u32,
) -> u32 {
    if device_id != WAVE_MAPPER && device_id != 0 {
        return MMSYSERR_BADDEVICEID;
    }
    let Some(format) = (unsafe { parse_wave_format(pwfx) }) else {
        return WAVERR_BADFORMAT;
    };
    if flags & WAVE_FORMAT_QUERY != 0 {
        return MMSYSERR_NOERROR;
    }
    if phwo.is_null() {
        return MMSYSERR_INVALPARAM;
    }
    let device = match start_wave_device(format, callback, flags) {
        Ok(device) => device,
        Err(error) => return error,
    };
    let handle = next_wave_handle();
    devices().write().expect("waveOut device registry poisoned").insert(handle, device);
    unsafe { phwo.write(handle) };
    trace!(
        handle,
        callback,
        instance,
        flags,
        ?format,
        "waveOutOpen using PulseAudio simple backend"
    );
    MMSYSERR_NOERROR
}

extern "win64" fn waveOutClose(handle: usize) -> u32 {
    let mut device = {
        let mut devices = devices().write().expect("waveOut device registry poisoned");
        let Some(device) = devices.get(&handle) else {
            return MMSYSERR_INVALHANDLE;
        };
        if device.pending.load(Ordering::Acquire) != 0 {
            return WAVERR_STILLPLAYING;
        }
        devices.remove(&handle).expect("device existed")
    };
    let (complete, done) = mpsc::channel();
    let _ = device.sender.send(WaveCommand::Shutdown { complete });
    let _ = done.recv_timeout(Duration::from_secs(1));
    if let Some(worker) = device.worker.take() {
        let _ = worker.join();
    }
    MMSYSERR_NOERROR
}

extern "win64" fn waveOutPrepareHeader(handle: usize, header: *mut u8, size: u32) -> u32 {
    if with_device(handle, |_| ()).is_none() {
        return MMSYSERR_INVALHANDLE;
    }
    if header.is_null() || size < WAVEHDR_SIZE {
        return MMSYSERR_INVALPARAM;
    }
    let header = header as usize;
    let flags = unsafe { header_flags(header) };
    if flags & WHDR_INQUEUE != 0 {
        return WAVERR_STILLPLAYING;
    }
    unsafe { set_header_flags(header, (flags | WHDR_PREPARED) & !WHDR_DONE) };
    MMSYSERR_NOERROR
}

extern "win64" fn waveOutWrite(handle: usize, header: *mut u8, size: u32) -> u32 {
    if header.is_null() || size < WAVEHDR_SIZE {
        return MMSYSERR_INVALPARAM;
    }
    let header_address = header as usize;
    let flags = unsafe { header_flags(header_address) };
    if flags & WHDR_PREPARED == 0 {
        return WAVERR_UNPREPARED;
    }
    if flags & WHDR_INQUEUE != 0 {
        return WAVERR_STILLPLAYING;
    }
    let data =
        unsafe { ((header_address + WAVEHDR_DATA) as *const usize).read_unaligned() as *const u8 };
    let length =
        unsafe { ((header_address + WAVEHDR_LENGTH) as *const u32).read_unaligned() as usize };
    if data.is_null() && length != 0 {
        return MMSYSERR_INVALPARAM;
    }
    let copied_data = if length == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, length).to_vec() }
    };
    let result = with_device(handle, |device| {
        unsafe { set_header_flags(header_address, (flags | WHDR_INQUEUE) & !WHDR_DONE) };
        device.pending.fetch_add(1, Ordering::Release);
        if device
            .sender
            .send(WaveCommand::Buffer { header: header_address, data: copied_data, event: 0 })
            .is_err()
        {
            device.pending.fetch_sub(1, Ordering::Release);
            unsafe { complete_header(header_address) };
            MMSYSERR_NODRIVER
        } else {
            MMSYSERR_NOERROR
        }
    });
    result.unwrap_or(MMSYSERR_INVALHANDLE)
}

extern "win64" fn waveOutUnprepareHeader(handle: usize, header: *mut u8, size: u32) -> u32 {
    if with_device(handle, |_| ()).is_none() {
        return MMSYSERR_INVALHANDLE;
    }
    if header.is_null() || size < WAVEHDR_SIZE {
        return MMSYSERR_INVALPARAM;
    }
    let header = header as usize;
    let flags = unsafe { header_flags(header) };
    if flags & WHDR_INQUEUE != 0 {
        return WAVERR_STILLPLAYING;
    }
    unsafe { set_header_flags(header, flags & !WHDR_PREPARED) };
    MMSYSERR_NOERROR
}

extern "win64" fn waveOutReset(handle: usize) -> u32 {
    let Some(sender) = with_device(handle, |device| device.sender.clone()) else {
        return MMSYSERR_INVALHANDLE;
    };
    let (complete, done) = mpsc::channel();
    if sender.send(WaveCommand::Reset { complete }).is_err() {
        return MMSYSERR_NODRIVER;
    }
    let _ = done.recv_timeout(Duration::from_secs(1));
    MMSYSERR_NOERROR
}

extern "win64" fn waveOutGetPosition(handle: usize, mmtime: *mut u8, size: u32) -> u32 {
    if mmtime.is_null() || size < 8 {
        return MMSYSERR_INVALPARAM;
    }
    let Some((format, completed)) = with_device(handle, |device| {
        (device.format, device.completed_bytes.load(Ordering::Relaxed))
    }) else {
        return MMSYSERR_INVALHANDLE;
    };
    let requested = unsafe { mmtime.cast::<u32>().read_unaligned() };
    let value = match requested {
        TIME_SAMPLES => completed / u64::from(format.block_align),
        TIME_BYTES => completed,
        TIME_MS | 0 => {
            completed.saturating_mul(1000) / u64::from(format.average_bytes_per_second.max(1))
        }
        _ => return MMSYSERR_INVALPARAM,
    }
    .min(u64::from(u32::MAX)) as u32;
    unsafe {
        mmtime.cast::<u32>().write_unaligned(if requested == 0 { TIME_MS } else { requested });
        mmtime.add(4).cast::<u32>().write_unaligned(value);
    }
    MMSYSERR_NOERROR
}

extern "win64" fn waveOutGetErrorTextW(error: u32, text: *mut u16, length: u32) -> u32 {
    if text.is_null() || length == 0 {
        return MMSYSERR_INVALPARAM;
    }
    let message = match error {
        MMSYSERR_NOERROR => "No error",
        WAVERR_BADFORMAT => "Unsupported wave format",
        MMSYSERR_NODRIVER => "No audio driver",
        _ => "Wave output error",
    };
    let utf16: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
    let copy = utf16.len().min(length as usize);
    unsafe { ptr::copy_nonoverlapping(utf16.as_ptr(), text, copy) };
    if copy == length as usize {
        unsafe { text.add(copy - 1).write(0) };
    }
    MMSYSERR_NOERROR
}

// Recording is intentionally still unavailable.  Advertising an output
// device, however, lets Unity's legacy WinMM output path initialize.
extern "win64" fn waveInGetNumDevs() -> u32 {
    0
}
extern "win64" fn waveInGetDevCapsW(_uDeviceID: usize, _pwic: *mut u8, _cbwic: u32) -> u32 {
    MMSYSERR_ERROR
}
extern "win64" fn waveInGetDevCapsA(_uDeviceID: usize, _pwic: *mut u8, _cbwic: u32) -> u32 {
    MMSYSERR_ERROR
}
extern "win64" fn waveInOpen(
    phwi: *mut usize,
    _uDeviceID: u32,
    _pwfx: *mut u8,
    _dwCallback: usize,
    _dwInstance: usize,
    _fdwOpen: u32,
) -> u32 {
    if !phwi.is_null() {
        unsafe { phwi.write(0) }
    };
    MMSYSERR_NODRIVER
}
extern "win64" fn waveInClose(_hwi: usize) -> u32 {
    MMSYSERR_NOERROR
}
extern "win64" fn waveInPrepareHeader(_hwi: usize, _pwh: *mut u8, _cbwh: u32) -> u32 {
    MMSYSERR_NOERROR
}
extern "win64" fn waveInAddBuffer(_hwi: usize, _pwh: *mut u8, _cbwh: u32) -> u32 {
    MMSYSERR_NOERROR
}
extern "win64" fn waveInStart(_hwi: usize) -> u32 {
    MMSYSERR_NODRIVER
}
extern "win64" fn waveInReset(_hwi: usize) -> u32 {
    MMSYSERR_NOERROR
}
extern "win64" fn waveInUnprepareHeader(_hwi: usize, _pwh: *mut u8, _cbwh: u32) -> u32 {
    MMSYSERR_NOERROR
}
extern "win64" fn midiOutGetNumDevs() -> u32 {
    0
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("timeGetTime", timeGetTime as usize);
    exports.insert("timeBeginPeriod", timeBeginPeriod as usize);
    exports.insert("timeEndPeriod", timeEndPeriod as usize);
    exports.insert("timeGetDevCaps", timeGetDevCaps as usize);
    exports.insert("timeSetEvent", timeSetEvent as usize);
    exports.insert("timeKillEvent", timeKillEvent as usize);
    exports.insert("waveOutGetNumDevs", waveOutGetNumDevs as usize);
    exports.insert("waveOutGetDevCapsW", waveOutGetDevCapsW as usize);
    exports.insert("waveOutGetDevCapsA", waveOutGetDevCapsA as usize);
    exports.insert("waveOutOpen", waveOutOpen as usize);
    exports.insert("waveOutClose", waveOutClose as usize);
    exports.insert("waveOutPrepareHeader", waveOutPrepareHeader as usize);
    exports.insert("waveOutWrite", waveOutWrite as usize);
    exports.insert("waveOutUnprepareHeader", waveOutUnprepareHeader as usize);
    exports.insert("waveOutReset", waveOutReset as usize);
    exports.insert("waveOutGetPosition", waveOutGetPosition as usize);
    exports.insert("waveOutGetErrorTextW", waveOutGetErrorTextW as usize);
    exports.insert("waveInGetNumDevs", waveInGetNumDevs as usize);
    exports.insert("waveInGetDevCapsW", waveInGetDevCapsW as usize);
    exports.insert("waveInGetDevCapsA", waveInGetDevCapsA as usize);
    exports.insert("waveInOpen", waveInOpen as usize);
    exports.insert("waveInClose", waveInClose as usize);
    exports.insert("waveInPrepareHeader", waveInPrepareHeader as usize);
    exports.insert("waveInAddBuffer", waveInAddBuffer as usize);
    exports.insert("waveInStart", waveInStart as usize);
    exports.insert("waveInReset", waveInReset as usize);
    exports.insert("waveInUnprepareHeader", waveInUnprepareHeader as usize);
    exports.insert("midiOutGetNumDevs", midiOutGetNumDevs as usize);
    exports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pcm_and_float_wave_format() {
        let pcm = [1, 0, 2, 0, 0x44, 0xac, 0, 0, 0x10, 0xb1, 2, 0, 4, 0, 16, 0, 0, 0];
        let parsed = unsafe { parse_wave_format(pcm.as_ptr()) }.expect("PCM format");
        assert_eq!(parsed.pulse_format, PA_SAMPLE_S16LE);
        assert_eq!(parsed.rate, 44_100);
        let float = [3, 0, 2, 0, 0x80, 0xbb, 0, 0, 0, 0xdc, 5, 0, 8, 0, 32, 0, 0, 0];
        assert_eq!(
            unsafe { parse_wave_format(float.as_ptr()) }.unwrap().pulse_format,
            PA_SAMPLE_FLOAT32LE
        );
    }

    #[test]
    fn invalid_format_is_rejected() {
        let invalid = [1, 0, 0, 0, 0x44, 0xac, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0];
        assert!(unsafe { parse_wave_format(invalid.as_ptr()) }.is_none());
    }

    #[test]
    fn prepare_and_unprepare_manage_header_flags() {
        let mut header = [0u8; WAVEHDR_SIZE as usize];
        unsafe { set_header_flags(header.as_mut_ptr() as usize, WHDR_DONE) };
        let before = unsafe { header_flags(header.as_ptr() as usize) };
        assert_eq!(before, WHDR_DONE);
        unsafe {
            set_header_flags(header.as_mut_ptr() as usize, (before | WHDR_PREPARED) & !WHDR_DONE)
        };
        assert_eq!(unsafe { header_flags(header.as_ptr() as usize) }, WHDR_PREPARED);
    }

    #[test]
    #[ignore = "requires the user's PulseAudio or PipeWire-Pulse server"]
    fn pulse_simple_backend_plays_a_real_desktop_buffer() {
        let format = [1, 0, 2, 0, 0x44, 0xac, 0, 0, 0x10, 0xb1, 2, 0, 4, 0, 16, 0, 0, 0];
        let mut handle = 0usize;
        assert_eq!(
            waveOutOpen(&mut handle, WAVE_MAPPER, format.as_ptr(), 0, 0, 0),
            MMSYSERR_NOERROR
        );
        let mut samples = vec![0u8; 1_764]; // 10ms of stereo S16 silence.
        let mut header = [0u8; WAVEHDR_SIZE as usize];
        unsafe {
            header.as_mut_ptr().cast::<usize>().write_unaligned(samples.as_mut_ptr() as usize);
            header
                .as_mut_ptr()
                .add(WAVEHDR_LENGTH)
                .cast::<u32>()
                .write_unaligned(samples.len() as u32);
        }
        assert_eq!(
            waveOutPrepareHeader(handle, header.as_mut_ptr(), WAVEHDR_SIZE),
            MMSYSERR_NOERROR
        );
        assert_eq!(waveOutWrite(handle, header.as_mut_ptr(), WAVEHDR_SIZE), MMSYSERR_NOERROR);
        for _ in 0..50 {
            if unsafe { header_flags(header.as_ptr() as usize) } & WHDR_DONE != 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_ne!(unsafe { header_flags(header.as_ptr() as usize) } & WHDR_DONE, 0);
        assert_eq!(
            waveOutUnprepareHeader(handle, header.as_mut_ptr(), WAVEHDR_SIZE),
            MMSYSERR_NOERROR
        );
        assert_eq!(waveOutClose(handle), MMSYSERR_NOERROR);
    }
}
