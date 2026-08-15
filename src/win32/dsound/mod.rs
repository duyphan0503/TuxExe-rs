#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::Path;
use std::{
    ptr,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Mutex,
    },
};
use tracing::{info, trace, warn};

const ERROR_SUCCESS: i32 = 0;
const ERROR_INVALID_PARAMETER: i32 = 87;
const DSERR_NODRIVER: i32 = 0x8878_0078u32 as i32;
const DSERR_BADFORMAT: i32 = 0x8878_0064u32 as i32;
const DSERR_INVALIDPARAM: i32 = 0x8878_006eu32 as i32;
const E_NOINTERFACE: i32 = 0x8000_4002u32 as i32;
const S_OK: i32 = 0;
const DS_OK: i32 = 0;
const DSBCAPS_PRIMARYBUFFER: u32 = 0x0000_0001;
const DSBPLAY_LOOPING: u32 = 0x0000_0001;
const DSBSTATUS_PLAYING: u32 = 0x0000_0001;
const DSBSTATUS_LOOPING: u32 = 0x0000_0004;
const DSBLOCK_FROMWRITECURSOR: u32 = 0x0000_0001;
const DSBLOCK_ENTIREBUFFER: u32 = 0x0000_0002;
const WAVE_FORMAT_PCM: u16 = 1;

// DirectSoundEnumerate always reports the default/primary driver with a
// NULL GUID before it reports concrete endpoints.  FMOD uses that ordering
// to decide whether the DirectSound backend is usable; returning only a
// made-up non-NULL endpoint makes it silently discard the backend before it
// ever calls DirectSoundCreate.
const PRIMARY_DEVICE_DESCRIPTION_A: &[u8] = b"Primary Sound Driver\0";
const DEFAULT_DEVICE_DESCRIPTION_A: &[u8] = b"TuxExe PulseAudio output\0";
const DEFAULT_DEVICE_MODULE_A: &[u8] = b"dsound.dll\0";
// A stable synthetic endpoint GUID. Some FMOD builds skip the documented
// NULL/default DirectSound GUID while enumerating devices, so advertising a
// concrete endpoint allows them to attempt DirectSoundCreate.
const DEFAULT_DEVICE_GUID: [u8; 16] = [
    0x52, 0x2f, 0x4d, 0x8a, 0x71, 0x6b, 0x4f, 0x20, 0x9c, 0xe1, 0x54, 0x75, 0x78, 0x45, 0x78, 0x65,
];
const PRIMARY_DEVICE_DESCRIPTION_W: &[u16] = &[
    80, 114, 105, 109, 97, 114, 121, 32, 83, 111, 117, 110, 100, 32, 68, 114, 105, 118, 101, 114, 0,
];
const DEFAULT_DEVICE_DESCRIPTION_W: &[u16] = &[
    84, 117, 120, 69, 120, 101, 32, 80, 117, 108, 115, 101, 65, 117, 100, 105, 111, 32, 111, 117,
    116, 112, 117, 116, 0,
];
const DEFAULT_DEVICE_MODULE_W: &[u16] = &[100, 115, 111, 117, 110, 100, 46, 100, 108, 108, 0];

type DirectSoundEnumerateCallbackA =
    unsafe extern "win64" fn(*const c_void, *const i8, *const i8, *mut c_void) -> i32;
type DirectSoundEnumerateCallbackW =
    unsafe extern "win64" fn(*const c_void, *const u16, *const u16, *mut c_void) -> i32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioBackend {
    PipeWire,
    PulseAudio,
    Null,
}

#[derive(Clone, Copy, Debug)]
struct SoundFormat {
    tag: u16,
    channels: u16,
    rate: u32,
    average_bytes_per_second: u32,
    block_align: u16,
    bits: u16,
}

impl Default for SoundFormat {
    fn default() -> Self {
        Self { tag: WAVE_FORMAT_PCM, channels: 2, rate: 44_100, average_bytes_per_second: 176_400, block_align: 4, bits: 16 }
    }
}

#[repr(C)]
struct DirectSoundVtbl {
    query_interface: extern "win64" fn(*mut c_void, *const u8, *mut *mut c_void) -> i32,
    add_ref: extern "win64" fn(*mut c_void) -> u32,
    release: extern "win64" fn(*mut c_void) -> u32,
    create_sound_buffer: extern "win64" fn(*mut c_void, *const u8, *mut *mut c_void, *mut c_void) -> i32,
    get_caps: extern "win64" fn(*mut c_void, *mut u8) -> i32,
    duplicate_sound_buffer: extern "win64" fn(*mut c_void, *mut c_void, *mut *mut c_void) -> i32,
    set_cooperative_level: extern "win64" fn(*mut c_void, usize, u32) -> i32,
    compact: extern "win64" fn(*mut c_void) -> i32,
    get_speaker_config: extern "win64" fn(*mut c_void, *mut u32) -> i32,
    set_speaker_config: extern "win64" fn(*mut c_void, u32) -> i32,
    initialize: extern "win64" fn(*mut c_void, *const c_void) -> i32,
    verify_certification: extern "win64" fn(*mut c_void, *mut u32) -> i32,
}

#[repr(C)]
struct DirectSoundBufferVtbl {
    query_interface: extern "win64" fn(*mut c_void, *const u8, *mut *mut c_void) -> i32,
    add_ref: extern "win64" fn(*mut c_void) -> u32,
    release: extern "win64" fn(*mut c_void) -> u32,
    get_caps: extern "win64" fn(*mut c_void, *mut u8) -> i32,
    get_current_position: extern "win64" fn(*mut c_void, *mut u32, *mut u32) -> i32,
    get_format: extern "win64" fn(*mut c_void, *mut u8, u32, *mut u32) -> i32,
    get_volume: extern "win64" fn(*mut c_void, *mut i32) -> i32,
    get_pan: extern "win64" fn(*mut c_void, *mut i32) -> i32,
    get_frequency: extern "win64" fn(*mut c_void, *mut u32) -> i32,
    get_status: extern "win64" fn(*mut c_void, *mut u32) -> i32,
    initialize: extern "win64" fn(*mut c_void, *mut c_void, *const u8) -> i32,
    lock: extern "win64" fn(*mut c_void, u32, u32, *mut *mut c_void, *mut u32, *mut *mut c_void, *mut u32, u32) -> i32,
    play: extern "win64" fn(*mut c_void, u32, u32, u32) -> i32,
    set_current_position: extern "win64" fn(*mut c_void, u32) -> i32,
    set_format: extern "win64" fn(*mut c_void, *const u8) -> i32,
    set_volume: extern "win64" fn(*mut c_void, i32) -> i32,
    set_pan: extern "win64" fn(*mut c_void, i32) -> i32,
    set_frequency: extern "win64" fn(*mut c_void, u32) -> i32,
    stop: extern "win64" fn(*mut c_void) -> i32,
    unlock: extern "win64" fn(*mut c_void, *mut c_void, u32, *mut c_void, u32) -> i32,
    restore: extern "win64" fn(*mut c_void) -> i32,
    set_fx: extern "win64" fn(*mut c_void, u32, *const c_void, *mut u32) -> i32,
    acquire_resources: extern "win64" fn(*mut c_void, u32, u32, *mut u32) -> i32,
    get_object_in_path: extern "win64" fn(*mut c_void, *const c_void, u32, *const c_void, *mut *mut c_void) -> i32,
}

#[repr(C)]
struct DirectSoundCom {
    vtbl: &'static DirectSoundVtbl,
    refs: AtomicU32,
}

#[repr(C)]
struct DirectSoundBufferCom {
    vtbl: &'static DirectSoundBufferVtbl,
    refs: AtomicU32,
    flags: u32,
    format: Mutex<SoundFormat>,
    bytes: Mutex<Vec<u8>>,
    stream: Mutex<Option<crate::win32::winmm::DesktopAudioStream>>,
    playing: AtomicBool,
    looping: AtomicBool,
    cursor: AtomicU32,
    play_start_time: Mutex<Option<std::time::Instant>>,
    play_start_offset: AtomicU32,
}

fn set_last_error(value: i32) {
    crate::win32::kernel32::error::set_last_error(value as u32);
}

pub fn detect_audio_backend() -> AudioBackend {
    if let Ok(backend) = std::env::var("TUXEXE_AUDIO_BACKEND") {
        return match backend.to_ascii_lowercase().as_str() {
            "pipewire" => AudioBackend::PipeWire,
            "pulse" | "pulseaudio" => AudioBackend::PulseAudio,
            _ => AudioBackend::Null,
        };
    }

    // PipeWire sockets are per-user.  `/run/pipewire-0` only happens to
    // work on a few system-wide configurations; the normal desktop path is
    // `$XDG_RUNTIME_DIR/pipewire-0` (for example `/run/user/1000`).
    if std::env::var_os("XDG_RUNTIME_DIR")
        .is_some_and(|runtime_dir| Path::new(&runtime_dir).join("pipewire-0").exists())
        || Path::new("/run/pipewire-0").exists()
    {
        return AudioBackend::PipeWire;
    }

    // PulseAudio may be discovered from its default per-user Unix socket
    // without PULSE_SERVER being explicitly set.
    if std::env::var("PULSE_SERVER").is_ok()
        || std::env::var_os("PULSE_RUNTIME_PATH")
            .is_some_and(|runtime_dir| Path::new(&runtime_dir).join("native").exists())
        || std::env::var_os("XDG_RUNTIME_DIR")
            .is_some_and(|runtime_dir| Path::new(&runtime_dir).join("pulse/native").exists())
    {
        return AudioBackend::PulseAudio;
    }

    AudioBackend::Null
}

fn parse_format(format: *const u8) -> Option<SoundFormat> {
    if format.is_null() { return None; }
    unsafe {
        let mut tag = format.cast::<u16>().read_unaligned();
        let channels = format.add(2).cast::<u16>().read_unaligned();
        let rate = format.add(4).cast::<u32>().read_unaligned();
        let average_bytes_per_second = format.add(8).cast::<u32>().read_unaligned();
        let block_align = format.add(12).cast::<u16>().read_unaligned();
        let bits = format.add(14).cast::<u16>().read_unaligned();
        if tag == 0xFFFE /* WAVE_FORMAT_EXTENSIBLE */ {
            let cb_size = format.add(16).cast::<u16>().read_unaligned();
            if cb_size >= 22 {
                // SubFormat GUID Data1 (offset 24)
                let sub_tag = format.add(24).cast::<u16>().read_unaligned();
                if sub_tag != 0 {
                    tag = sub_tag;
                }
            }
        }
        (channels != 0 && rate != 0 && block_align != 0).then_some(SoundFormat { tag, channels, rate, average_bytes_per_second, block_align, bits })
    }
}

fn buffer_from_this(this: *mut c_void) -> Option<&'static DirectSoundBufferCom> {
    (!this.is_null()).then(|| unsafe { &*this.cast::<DirectSoundBufferCom>() })
}

extern "win64" fn device_query_interface(this: *mut c_void, _iid: *const u8, output: *mut *mut c_void) -> i32 {
    info!(this = ?this, output = ?output, "DirectSound::QueryInterface");
    if output.is_null() { return DSERR_INVALIDPARAM; }
    unsafe { output.write(this); }
    device_add_ref(this);
    S_OK
}
extern "win64" fn device_add_ref(this: *mut c_void) -> u32 {
    info!(this = ?this, "DirectSound::AddRef");
    if this.is_null() { return 0; }
    unsafe { (&*this.cast::<DirectSoundCom>()).refs.fetch_add(1, Ordering::Relaxed) + 1 }
}
extern "win64" fn device_release(this: *mut c_void) -> u32 {
    info!(this = ?this, "DirectSound::Release");
    if this.is_null() { return 0; }
    let refs = &unsafe { &*this.cast::<DirectSoundCom>() }.refs;
    let current = refs.load(Ordering::Acquire);
    if current == 0 { 0 } else { refs.fetch_sub(1, Ordering::Release) - 1 }
}
extern "win64" fn device_create_sound_buffer(this: *mut c_void, desc: *const u8, output: *mut *mut c_void, _outer: *mut c_void) -> i32 {
    info!(this = ?this, desc = ?desc, output = ?output, "DirectSound::CreateSoundBuffer");
    if this.is_null() || desc.is_null() || output.is_null() { return DSERR_INVALIDPARAM; }
    let size = unsafe { desc.add(8).cast::<u32>().read_unaligned() };
    let flags = unsafe { desc.add(4).cast::<u32>().read_unaligned() };
    let format_ptr = unsafe { desc.add(16).cast::<*const u8>().read_unaligned() };
    info!(flags, size, format = ?format_ptr, "DirectSound buffer descriptor");
    let format = if format_ptr.is_null() { SoundFormat::default() } else if let Some(format) = parse_format(format_ptr) { format } else { warn!(format = ?format_ptr, "DirectSound rejected invalid WAVEFORMATEX"); return DSERR_BADFORMAT };
    let size = if flags & DSBCAPS_PRIMARYBUFFER != 0 { size.max(4_096) } else { size };
    if size == 0 { warn!(flags, "DirectSound rejected zero-sized secondary buffer"); return DSERR_INVALIDPARAM; }
    let object = Box::new(DirectSoundBufferCom {
        vtbl: &DIRECT_SOUND_BUFFER_VTBL, refs: AtomicU32::new(1), flags,
        format: Mutex::new(format), bytes: Mutex::new(vec![0; size as usize]), stream: Mutex::new(None),
        playing: AtomicBool::new(false), looping: AtomicBool::new(false), cursor: AtomicU32::new(0),
        play_start_time: Mutex::new(None), play_start_offset: AtomicU32::new(0),
    });
    let raw = Box::into_raw(object).cast::<c_void>();
    unsafe { output.write(raw); }
    info!(flags, size, ?format, "DirectSound CreateSoundBuffer");
    S_OK
}
extern "win64" fn device_get_caps(_this: *mut c_void, caps: *mut u8) -> i32 {
    info!(caps = ?caps, "DirectSound::GetCaps");
    if caps.is_null() { return DSERR_INVALIDPARAM; }
    unsafe {
        let size = caps.cast::<u32>().read_unaligned();
        if size < 4 { return DSERR_INVALIDPARAM; }
        ptr::write_bytes(caps, 0, size as usize);
        caps.cast::<u32>().write_unaligned(size);
        if size >= 8 {
            let flags = 0x0000_0001 /* DSCAPS_PRIMARYMONO */
                | 0x0000_0002 /* DSCAPS_PRIMARYSTEREO */
                | 0x0000_0004 /* DSCAPS_PRIMARY8BIT */
                | 0x0000_0008 /* DSCAPS_PRIMARY16BIT */
                | 0x0000_0010 /* DSCAPS_CONTINUOUSRATE */
                | 0x0000_0040 /* DSCAPS_CERTIFIED */
                | 0x0000_0100 /* DSCAPS_SECONDARYMONO */
                | 0x0000_0200 /* DSCAPS_SECONDARYSTEREO */
                | 0x0000_0400 /* DSCAPS_SECONDARY8BIT */
                | 0x0000_0800 /* DSCAPS_SECONDARY16BIT */;
            caps.add(4).cast::<u32>().write_unaligned(flags);
        }
        if size >= 12 {
            caps.add(8).cast::<u32>().write_unaligned(100);
        }
        if size >= 16 {
            caps.add(12).cast::<u32>().write_unaligned(192_000);
        }
        if size >= 20 {
            caps.add(16).cast::<u32>().write_unaligned(1);
        }
        if size >= 24 {
            caps.add(20).cast::<u32>().write_unaligned(1);
        }
        if size >= 28 {
            caps.add(24).cast::<u32>().write_unaligned(1);
        }
        if size >= 32 {
            caps.add(28).cast::<u32>().write_unaligned(1);
        }
        if size >= 36 {
            caps.add(32).cast::<u32>().write_unaligned(1);
        }
        if size >= 40 {
            caps.add(36).cast::<u32>().write_unaligned(1);
        }
        if size >= 44 {
            caps.add(40).cast::<u32>().write_unaligned(1);
        }
    }
    S_OK
}
extern "win64" fn device_duplicate_sound_buffer(_this: *mut c_void, _source: *mut c_void, output: *mut *mut c_void) -> i32 { if !output.is_null() { unsafe { output.write(ptr::null_mut()) }; } DSERR_INVALIDPARAM }
extern "win64" fn device_set_cooperative_level(_this: *mut c_void, _window: usize, _level: u32) -> i32 { info!("DirectSound::SetCooperativeLevel"); S_OK }
extern "win64" fn device_compact(_this: *mut c_void) -> i32 { S_OK }
extern "win64" fn device_get_speaker_config(_this: *mut c_void, output: *mut u32) -> i32 { if output.is_null() { return DSERR_INVALIDPARAM; } unsafe { output.write(0x0000_0004) }; S_OK }
extern "win64" fn device_set_speaker_config(_this: *mut c_void, _config: u32) -> i32 { S_OK }
extern "win64" fn device_initialize(_this: *mut c_void, _guid: *const c_void) -> i32 { S_OK }
extern "win64" fn device_verify_certification(_this: *mut c_void, output: *mut u32) -> i32 { if output.is_null() { return DSERR_INVALIDPARAM; } unsafe { output.write(0) }; S_OK }

extern "win64" fn buffer_query_interface(this: *mut c_void, _iid: *const u8, output: *mut *mut c_void) -> i32 {
    info!(this = ?this, output = ?output, "DirectSoundBuffer::QueryInterface");
    if output.is_null() { return DSERR_INVALIDPARAM; }
    unsafe { output.write(this) };
    buffer_add_ref(this);
    S_OK
}
extern "win64" fn buffer_add_ref(this: *mut c_void) -> u32 {
    buffer_from_this(this).map(|b| b.refs.fetch_add(1, Ordering::Relaxed) + 1).unwrap_or(0)
}
extern "win64" fn buffer_release(this: *mut c_void) -> u32 {
    info!(this = ?this, "DirectSoundBuffer::Release");
    let Some(buffer) = buffer_from_this(this) else { return 0; };
    let current = buffer.refs.load(Ordering::Acquire);
    if current == 0 { 0 } else { buffer.refs.fetch_sub(1, Ordering::Release) - 1 }
}
extern "win64" fn buffer_get_caps(this: *mut c_void, caps: *mut u8) -> i32 {
    info!(this = ?this, "DirectSoundBuffer::GetCaps");
    let Some(buffer) = buffer_from_this(this) else { return DSERR_INVALIDPARAM; };
    if caps.is_null() { return DSERR_INVALIDPARAM; }
    unsafe {
        let size = caps.cast::<u32>().read_unaligned();
        if size < 12 { return DSERR_INVALIDPARAM; }
        ptr::write_bytes(caps, 0, size as usize);
        caps.cast::<u32>().write_unaligned(size);
        caps.add(4).cast::<u32>().write_unaligned(buffer.flags);
        caps.add(8).cast::<u32>().write_unaligned(buffer.bytes.lock().expect("buffer bytes poisoned").len() as u32);
    }
    S_OK
}

fn calculate_current_play_position(buffer: &DirectSoundBufferCom) -> u32 {
    let len = buffer.bytes.lock().expect("buffer bytes poisoned").len() as u32;
    if len == 0 {
        return 0;
    }
    if !buffer.playing.load(Ordering::Acquire) {
        return buffer.cursor.load(Ordering::Relaxed) % len;
    }
    let start_time_guard = buffer.play_start_time.lock().expect("play_start_time poisoned");
    let Some(start_time) = *start_time_guard else {
        return buffer.cursor.load(Ordering::Relaxed) % len;
    };
    let format = *buffer.format.lock().expect("format poisoned");
    let bytes_per_sec = format.average_bytes_per_second.max(1) as u64;
    let elapsed = start_time.elapsed();
    let bytes_elapsed = (elapsed.as_secs() * bytes_per_sec) + (elapsed.subsec_nanos() as u64 * bytes_per_sec / 1_000_000_000);
    let start_offset = buffer.play_start_offset.load(Ordering::Relaxed) as u64;
    ((start_offset + bytes_elapsed) % (len as u64)) as u32
}

extern "win64" fn buffer_get_current_position(this: *mut c_void, play: *mut u32, write: *mut u32) -> i32 {
    let Some(buffer) = buffer_from_this(this) else { return DSERR_INVALIDPARAM; };
    let len = buffer.bytes.lock().expect("buffer bytes poisoned").len() as u32;
    let play_pos = calculate_current_play_position(buffer);
    let format = *buffer.format.lock().expect("format poisoned");
    let write_margin = (format.average_bytes_per_second / 50).clamp(512, (len / 4).max(512));
    let write_pos = if len == 0 { 0 } else { (play_pos + write_margin) % len };
    if !play.is_null() { unsafe { play.write(play_pos) }; }
    if !write.is_null() { unsafe { write.write(write_pos) }; }
    S_OK
}
extern "win64" fn buffer_get_format(this: *mut c_void, output: *mut u8, bytes: u32, written: *mut u32) -> i32 {
    info!(this = ?this, "DirectSoundBuffer::GetFormat");
    let Some(buffer) = buffer_from_this(this) else { return DSERR_INVALIDPARAM; };
    const FORMAT_SIZE: u32 = 18;
    if !written.is_null() { unsafe { written.write(FORMAT_SIZE) }; }
    if output.is_null() { return S_OK; }
    if bytes < 16 { return DSERR_INVALIDPARAM; }
    let f = *buffer.format.lock().expect("buffer format poisoned");
    unsafe {
        output.cast::<u16>().write_unaligned(f.tag);
        output.add(2).cast::<u16>().write_unaligned(f.channels);
        output.add(4).cast::<u32>().write_unaligned(f.rate);
        output.add(8).cast::<u32>().write_unaligned(f.average_bytes_per_second);
        output.add(12).cast::<u16>().write_unaligned(f.block_align);
        output.add(14).cast::<u16>().write_unaligned(f.bits);
        if bytes >= FORMAT_SIZE { output.add(16).cast::<u16>().write_unaligned(0); }
    }
    S_OK
}
extern "win64" fn buffer_get_volume(_this: *mut c_void, output: *mut i32) -> i32 {
    if output.is_null() { return DSERR_INVALIDPARAM; }
    unsafe { output.write(0) };
    S_OK
}
extern "win64" fn buffer_get_pan(_this: *mut c_void, output: *mut i32) -> i32 {
    if output.is_null() { return DSERR_INVALIDPARAM; }
    unsafe { output.write(0) };
    S_OK
}
extern "win64" fn buffer_get_frequency(this: *mut c_void, output: *mut u32) -> i32 {
    let Some(buffer) = buffer_from_this(this) else { return DSERR_INVALIDPARAM; };
    if output.is_null() { return DSERR_INVALIDPARAM; }
    unsafe { output.write(buffer.format.lock().expect("buffer format poisoned").rate) };
    S_OK
}
extern "win64" fn buffer_get_status(this: *mut c_void, output: *mut u32) -> i32 {
    let Some(buffer) = buffer_from_this(this) else { return DSERR_INVALIDPARAM; };
    if output.is_null() { return DSERR_INVALIDPARAM; }
    let mut state = 0;
    if buffer.playing.load(Ordering::Acquire) { state |= DSBSTATUS_PLAYING; }
    if buffer.looping.load(Ordering::Acquire) { state |= DSBSTATUS_LOOPING; }
    unsafe { output.write(state) };
    S_OK
}
extern "win64" fn buffer_initialize(_this: *mut c_void, _device: *mut c_void, _desc: *const u8) -> i32 { S_OK }
extern "win64" fn buffer_lock(
    this: *mut c_void,
    mut offset: u32,
    mut requested: u32,
    first: *mut *mut c_void,
    first_size: *mut u32,
    second: *mut *mut c_void,
    second_size: *mut u32,
    flags: u32,
) -> i32 {
    let Some(buffer) = buffer_from_this(this) else { return DSERR_INVALIDPARAM; };
    if first.is_null() || first_size.is_null() || second.is_null() || second_size.is_null() { return DSERR_INVALIDPARAM; }
    let bytes = buffer.bytes.lock().expect("buffer bytes poisoned");
    let len = bytes.len();
    if len == 0 { return DSERR_INVALIDPARAM; }

    if flags & DSBLOCK_FROMWRITECURSOR != 0 {
        let play_pos = calculate_current_play_position(buffer);
        let format = *buffer.format.lock().expect("format poisoned");
        let write_margin = (format.average_bytes_per_second / 50).clamp(512, (len as u32 / 4).max(512));
        offset = (play_pos + write_margin) % (len as u32);
    }
    if flags & DSBLOCK_ENTIREBUFFER != 0 {
        requested = len as u32;
    }

    let offset = (offset as usize) % len;
    let requested = if requested == 0 { len - offset } else { (requested as usize).min(len) };
    let first_len = requested.min(len - offset);
    let second_len = requested - first_len;
    let base = bytes.as_ptr() as *mut u8;
    unsafe {
        first.write(base.add(offset).cast());
        first_size.write(first_len as u32);
        second.write(if second_len == 0 { ptr::null_mut() } else { base.cast() });
        second_size.write(second_len as u32);
    }
    S_OK
}
extern "win64" fn buffer_play(this: *mut c_void, _reserved1: u32, _priority: u32, flags: u32) -> i32 {
    info!(this = ?this, flags, "DirectSoundBuffer::Play");
    let Some(buffer) = buffer_from_this(this) else { return DSERR_INVALIDPARAM; };
    buffer.playing.store(true, Ordering::Release);
    buffer.looping.store(flags & DSBPLAY_LOOPING != 0, Ordering::Release);
    *buffer.play_start_time.lock().expect("play_start_time poisoned") = Some(std::time::Instant::now());
    buffer.play_start_offset.store(buffer.cursor.load(Ordering::Relaxed), Ordering::Release);
    let format = *buffer.format.lock().expect("buffer format poisoned");
    let mut stream = buffer.stream.lock().expect("buffer stream poisoned");
    if stream.is_none() {
        *stream = crate::win32::winmm::DesktopAudioStream::open(format.tag, format.channels, format.rate, format.bits);
        info!(opened = stream.is_some(), ?format, "DirectSound buffer_play opened DesktopAudioStream");
    }
    S_OK
}
extern "win64" fn buffer_set_current_position(this: *mut c_void, position: u32) -> i32 {
    let Some(buffer) = buffer_from_this(this) else { return DSERR_INVALIDPARAM; };
    let len = buffer.bytes.lock().expect("buffer bytes poisoned").len() as u32;
    let pos = if len == 0 { 0 } else { position % len };
    buffer.cursor.store(pos, Ordering::Release);
    buffer.play_start_offset.store(pos, Ordering::Release);
    *buffer.play_start_time.lock().expect("play_start_time poisoned") = Some(std::time::Instant::now());
    S_OK
}
extern "win64" fn buffer_set_format(this: *mut c_void, format: *const u8) -> i32 {
    info!(this = ?this, format = ?format, "DirectSoundBuffer::SetFormat");
    let Some(buffer) = buffer_from_this(this) else { return DSERR_INVALIDPARAM; };
    let Some(format) = parse_format(format) else { return DSERR_BADFORMAT; };
    *buffer.format.lock().expect("buffer format poisoned") = format;
    *buffer.stream.lock().expect("buffer stream poisoned") = None;
    S_OK
}
extern "win64" fn buffer_set_volume(_this: *mut c_void, _value: i32) -> i32 { S_OK }
extern "win64" fn buffer_set_pan(_this: *mut c_void, _value: i32) -> i32 { S_OK }
extern "win64" fn buffer_set_frequency(this: *mut c_void, value: u32) -> i32 {
    let Some(buffer) = buffer_from_this(this) else { return DSERR_INVALIDPARAM; };
    if value == 0 { return DSERR_INVALIDPARAM; }
    buffer.format.lock().expect("buffer format poisoned").rate = value;
    *buffer.stream.lock().expect("buffer stream poisoned") = None;
    S_OK
}
extern "win64" fn buffer_stop(this: *mut c_void) -> i32 {
    info!(this = ?this, "DirectSoundBuffer::Stop");
    let Some(buffer) = buffer_from_this(this) else { return DSERR_INVALIDPARAM; };
    let current_pos = calculate_current_play_position(buffer);
    buffer.cursor.store(current_pos, Ordering::Release);
    buffer.playing.store(false, Ordering::Release);
    buffer.looping.store(false, Ordering::Release);
    *buffer.play_start_time.lock().expect("play_start_time poisoned") = None;
    S_OK
}
extern "win64" fn buffer_unlock(this: *mut c_void, first: *mut c_void, first_size: u32, second: *mut c_void, second_size: u32) -> i32 {
    let Some(buffer) = buffer_from_this(this) else { return DSERR_INVALIDPARAM; };
    let format = *buffer.format.lock().expect("buffer format poisoned");
    let mut stream = buffer.stream.lock().expect("buffer stream poisoned");
    if stream.is_none() {
        *stream = crate::win32::winmm::DesktopAudioStream::open(format.tag, format.channels, format.rate, format.bits);
        info!(opened = stream.is_some(), ?format, "DirectSound buffer_unlock opened DesktopAudioStream");
    }
    let mut written_bytes = 0usize;
    if let Some(stream_ref) = stream.as_mut() {
        if !first.is_null() && first_size > 0 {
            let slice = unsafe { std::slice::from_raw_parts(first.cast::<u8>(), first_size as usize) };
            let _ = stream_ref.write(slice);
            written_bytes += first_size as usize;
        }
        if !second.is_null() && second_size > 0 {
            let slice = unsafe { std::slice::from_raw_parts(second.cast::<u8>(), second_size as usize) };
            let _ = stream_ref.write(slice);
            written_bytes += second_size as usize;
        }
    }
    let buf_len = buffer.bytes.lock().expect("buffer bytes poisoned").len().max(1);
    let next = (buffer.cursor.load(Ordering::Relaxed) as usize + written_bytes) % buf_len;
    buffer.cursor.store(next as u32, Ordering::Release);
    S_OK
}
extern "win64" fn buffer_restore(_this: *mut c_void) -> i32 { S_OK }
extern "win64" fn buffer_set_fx(_this: *mut c_void, _count: u32, _fx: *const c_void, results: *mut u32) -> i32 { if !results.is_null() { unsafe { results.write(0) }; } S_OK }
extern "win64" fn buffer_acquire_resources(_this: *mut c_void, _flags: u32, _count: u32, results: *mut u32) -> i32 { if !results.is_null() { unsafe { results.write(0) }; } S_OK }
extern "win64" fn buffer_get_object_in_path(_this: *mut c_void, _guid: *const c_void, _index: u32, _iid: *const c_void, output: *mut *mut c_void) -> i32 { if !output.is_null() { unsafe { output.write(ptr::null_mut()) }; } E_NOINTERFACE }

static DIRECT_SOUND_VTBL: DirectSoundVtbl = DirectSoundVtbl { query_interface: device_query_interface, add_ref: device_add_ref, release: device_release, create_sound_buffer: device_create_sound_buffer, get_caps: device_get_caps, duplicate_sound_buffer: device_duplicate_sound_buffer, set_cooperative_level: device_set_cooperative_level, compact: device_compact, get_speaker_config: device_get_speaker_config, set_speaker_config: device_set_speaker_config, initialize: device_initialize, verify_certification: device_verify_certification };
static DIRECT_SOUND_BUFFER_VTBL: DirectSoundBufferVtbl = DirectSoundBufferVtbl { query_interface: buffer_query_interface, add_ref: buffer_add_ref, release: buffer_release, get_caps: buffer_get_caps, get_current_position: buffer_get_current_position, get_format: buffer_get_format, get_volume: buffer_get_volume, get_pan: buffer_get_pan, get_frequency: buffer_get_frequency, get_status: buffer_get_status, initialize: buffer_initialize, lock: buffer_lock, play: buffer_play, set_current_position: buffer_set_current_position, set_format: buffer_set_format, set_volume: buffer_set_volume, set_pan: buffer_set_pan, set_frequency: buffer_set_frequency, stop: buffer_stop, unlock: buffer_unlock, restore: buffer_restore, set_fx: buffer_set_fx, acquire_resources: buffer_acquire_resources, get_object_in_path: buffer_get_object_in_path };

fn create_device(output: *mut *mut c_void) -> i32 {
    if output.is_null() { return DSERR_INVALIDPARAM; }
    let object = Box::new(DirectSoundCom { vtbl: &DIRECT_SOUND_VTBL, refs: AtomicU32::new(1) });
    let raw = Box::into_raw(object).cast();
    info!(device = ?raw, "DirectSound COM device created");
    unsafe { output.write(raw); }
    S_OK
}

pub extern "win64" fn DirectSoundCreate(
    _lpcGuid: *const c_void,
    ppDS: *mut usize,
    _pUnkOuter: *mut c_void,
) -> i32 {
    info!("DirectSoundCreate called");
    let status = create_device(ppDS.cast());
    set_last_error(if status == S_OK { 0 } else { ERROR_INVALID_PARAMETER });
    status
}

pub extern "win64" fn DirectSoundCaptureCreate(
    _lpcGuidCapture: *const c_void,
    ppDSCapture: *mut usize,
    _pUnkOuter: *mut c_void,
) -> i32 {
    info!("DirectSoundCaptureCreate called");
    if ppDSCapture.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return ERROR_INVALID_PARAMETER;
    }

    unsafe {
        *ppDSCapture = 0;
    }
    set_last_error(0);
    DSERR_NODRIVER
}

pub extern "win64" fn DirectSoundCreate8(
    _guid: *const c_void,
    device: *mut *mut c_void,
    _outer: *mut c_void,
) -> i32 {
    info!(guid = ?_guid, device = ?device, outer = ?_outer, "DirectSoundCreate8 called");
    let status = create_device(device);
    set_last_error(if status == S_OK { 0 } else { ERROR_INVALID_PARAMETER });
    status
}

pub extern "win64" fn DirectSoundCaptureCreate8(
    _guid: *const c_void,
    device: *mut *mut c_void,
    _outer: *mut c_void,
) -> i32 {
    info!("DirectSoundCaptureCreate8 called");
    DirectSoundCreate8(std::ptr::null(), device, std::ptr::null_mut())
}

/// A successful empty enumeration is the standard DirectSound signal that no
/// compatible output device is present. It is safer than a generic stub
/// because no uninitialised callback/output data escapes to the caller.
pub extern "win64" fn DirectSoundEnumerateA(callback: *const c_void, context: *mut c_void) -> i32 {
    info!(callback = !callback.is_null(), "DirectSoundEnumerateA called");
    if !callback.is_null() {
        let callback: DirectSoundEnumerateCallbackA = unsafe { std::mem::transmute(callback) };
        let primary_result = unsafe {
            callback(
                std::ptr::null(),
                PRIMARY_DEVICE_DESCRIPTION_A.as_ptr().cast(),
                DEFAULT_DEVICE_MODULE_A.as_ptr().cast(),
                context,
            )
        };
        info!(result = primary_result, "DirectSoundEnumerateA primary callback completed");
        if primary_result == 0 {
            set_last_error(0);
            return ERROR_SUCCESS;
        }
        let result = unsafe {
            callback(
                DEFAULT_DEVICE_GUID.as_ptr().cast(),
                DEFAULT_DEVICE_DESCRIPTION_A.as_ptr().cast(),
                DEFAULT_DEVICE_MODULE_A.as_ptr().cast(),
                context,
            )
        };
        info!(result, "DirectSoundEnumerateA callback completed");
    }
    set_last_error(0);
    ERROR_SUCCESS
}

pub extern "win64" fn DirectSoundEnumerateW(callback: *const c_void, context: *mut c_void) -> i32 {
    info!(callback = !callback.is_null(), "DirectSoundEnumerateW called");
    if !callback.is_null() {
        let callback: DirectSoundEnumerateCallbackW = unsafe { std::mem::transmute(callback) };
        let primary_result = unsafe {
            callback(
                std::ptr::null(),
                PRIMARY_DEVICE_DESCRIPTION_W.as_ptr(),
                DEFAULT_DEVICE_MODULE_W.as_ptr(),
                context,
            )
        };
        info!(result = primary_result, "DirectSoundEnumerateW primary callback completed");
        if primary_result == 0 {
            set_last_error(0);
            return ERROR_SUCCESS;
        }
        let result = unsafe {
            callback(
                DEFAULT_DEVICE_GUID.as_ptr().cast(),
                DEFAULT_DEVICE_DESCRIPTION_W.as_ptr(),
                DEFAULT_DEVICE_MODULE_W.as_ptr(),
                context,
            )
        };
        info!(result, "DirectSoundEnumerateW callback completed");
    }
    set_last_error(0);
    ERROR_SUCCESS
}

pub extern "win64" fn DirectSoundCaptureEnumerateA(
    callback: *const c_void,
    context: *mut c_void,
) -> i32 {
    info!(callback = !callback.is_null(), "DirectSoundCaptureEnumerateA called");
    DirectSoundEnumerateA(callback, context)
}

pub extern "win64" fn DirectSoundCaptureEnumerateW(
    callback: *const c_void,
    context: *mut c_void,
) -> i32 {
    info!(callback = !callback.is_null(), "DirectSoundCaptureEnumerateW called");
    DirectSoundEnumerateW(callback, context)
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();
    exports.insert("DirectSoundCreate", DirectSoundCreate as usize);
    exports.insert("DirectSoundCreate8", DirectSoundCreate8 as usize);
    exports.insert("DirectSoundCaptureCreate", DirectSoundCaptureCreate as usize);
    exports.insert("DirectSoundCaptureCreate8", DirectSoundCaptureCreate8 as usize);
    exports.insert("DirectSoundEnumerateA", DirectSoundEnumerateA as usize);
    exports.insert("DirectSoundEnumerateW", DirectSoundEnumerateW as usize);
    exports.insert("DirectSoundCaptureEnumerateA", DirectSoundCaptureEnumerateA as usize);
    exports.insert("DirectSoundCaptureEnumerateW", DirectSoundCaptureEnumerateW as usize);
    exports
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::serial_guard;

    #[test]
    fn env_override_selects_backend() {
        let _guard = serial_guard();
        std::env::set_var("TUXEXE_AUDIO_BACKEND", "pulse");
        assert_eq!(detect_audio_backend(), AudioBackend::PulseAudio);
        std::env::remove_var("TUXEXE_AUDIO_BACKEND");
    }

    #[test]
    fn invalid_override_forces_null_backend() {
        let _guard = serial_guard();
        std::env::set_var("TUXEXE_AUDIO_BACKEND", "not-a-backend");
        assert_eq!(detect_audio_backend(), AudioBackend::Null);
        std::env::remove_var("TUXEXE_AUDIO_BACKEND");
    }

    #[test]
    fn discovers_pipewire_in_the_user_runtime_directory() {
        let _guard = serial_guard();
        let runtime_dir = tempfile::tempdir().expect("create temporary runtime directory");
        std::fs::write(runtime_dir.path().join("pipewire-0"), []).expect("create PipeWire socket marker");
        std::env::set_var("XDG_RUNTIME_DIR", runtime_dir.path());
        assert_eq!(detect_audio_backend(), AudioBackend::PipeWire);
        std::env::remove_var("XDG_RUNTIME_DIR");
    }

    #[test]
    fn directsound_create_returns_a_valid_com_object() {
        let _guard = serial_guard();
        let mut handle = 0usize;
        let status = DirectSoundCreate(std::ptr::null(), &raw mut handle, std::ptr::null_mut());
        assert_eq!(status, S_OK);
        assert_ne!(handle, 0);
        let object = handle as *mut DirectSoundCom;
        let refs = unsafe { ((*object).vtbl.release)(object.cast()) };
        assert_eq!(refs, 0);
    }

    #[test]
    fn directsound_com_creates_and_locks_a_pcm_buffer() {
        let _guard = serial_guard();
        let mut device = ptr::null_mut();
        assert_eq!(DirectSoundCreate8(ptr::null(), &raw mut device, ptr::null_mut()), S_OK);

        let format = [
            1, 0, // WAVE_FORMAT_PCM
            2, 0, // stereo
            0x44, 0xac, 0, 0, // 44.1 kHz
            0x10, 0xb1, 2, 0, // 176400 bytes/s
            4, 0, 16, 0, 0, 0,
        ];
        let mut desc = [0u8; 40];
        unsafe {
            desc.as_mut_ptr().cast::<u32>().write_unaligned(40);
            desc.as_mut_ptr().add(8).cast::<u32>().write_unaligned(256);
            desc.as_mut_ptr().add(16).cast::<*const u8>().write_unaligned(format.as_ptr());
        }
        let mut buffer = ptr::null_mut();
        let vtbl = unsafe { (*(device as *mut DirectSoundCom)).vtbl };
        assert_eq!((vtbl.create_sound_buffer)(device, desc.as_ptr(), &raw mut buffer, ptr::null_mut()), S_OK);
        assert!(!buffer.is_null());

        let buffer_vtbl = unsafe { (*(buffer as *mut DirectSoundBufferCom)).vtbl };
        let mut first = ptr::null_mut();
        let mut first_bytes = 0;
        let mut second = ptr::null_mut();
        let mut second_bytes = 0;
        assert_eq!(
            (buffer_vtbl.lock)(buffer, 240, 32, &raw mut first, &raw mut first_bytes, &raw mut second, &raw mut second_bytes, 0),
            S_OK
        );
        assert_eq!(first_bytes, 16);
        assert_eq!(second_bytes, 16);
        unsafe { ptr::write_bytes(first, 0x7f, first_bytes as usize) };
        unsafe { ptr::write_bytes(second, 0x55, second_bytes as usize) };
        assert_eq!((buffer_vtbl.unlock)(buffer, first, first_bytes, second, second_bytes), S_OK);
        assert_eq!((buffer_vtbl.release)(buffer), 0);
        assert_eq!((vtbl.release)(device), 0);
    }
}
