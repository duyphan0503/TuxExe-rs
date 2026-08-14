mod vk_thunks;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::sync::atomic::{AtomicPtr, Ordering};
use tracing::{info, trace};

static VULKAN_LIB: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());

fn get_vulkan_handle() -> *mut std::ffi::c_void {
    let mut handle = VULKAN_LIB.load(Ordering::Relaxed);
    if handle.is_null() {
        let name = CString::new("libvulkan.so.1").unwrap();
        handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL) };
        VULKAN_LIB.store(handle, Ordering::Relaxed);
    }
    handle
}

macro_rules! vulkan_stub {
    ($name:ident, $($arg:ident: $type:ty),*) => {
        pub extern "win64" fn $name($($arg: $type),*) -> u64 {
            let handle = get_vulkan_handle();
            if handle.is_null() { return 0; }
            type RealFn = unsafe extern "C" fn($($type),*) -> u64;
            let real_proc: Option<RealFn> = unsafe {
                let sym = CString::new(stringify!($name)).unwrap();
                let ptr = libc::dlsym(handle, sym.as_ptr());
                if !ptr.is_null() { Some(std::mem::transmute(ptr)) } else { None }
            };
            if let Some(f) = real_proc {
                unsafe { f($($arg),*) }
            } else {
                0
            }
        }
    };
}

#[repr(C)]
pub struct VkExtensionProperties {
    pub extension_name: [libc::c_char; 256],
    pub spec_version: u32,
}

#[repr(C)]
pub struct VkInstanceCreateInfo {
    pub s_type: u32,
    pub p_next: *const std::ffi::c_void,
    pub flags: u32,
    pub p_application_info: *const std::ffi::c_void,
    pub enabled_layer_count: u32,
    pub pp_enabled_layer_names: *const *const libc::c_char,
    pub enabled_extension_count: u32,
    pub pp_enabled_extension_names: *const *const libc::c_char,
}

#[repr(C)]
pub struct VkWin32SurfaceCreateInfoKHR {
    s_type: u32,
    p_next: *const std::ffi::c_void,
    flags: u32,
    hinstance: usize,
    hwnd: usize,
}

#[repr(C)]
pub struct VkXlibSurfaceCreateInfoKHR {
    s_type: u32,
    p_next: *const std::ffi::c_void,
    flags: u32,
    dpy: *mut std::ffi::c_void,
    window: usize,
}

pub extern "win64" fn vkCreateWin32SurfaceKHR(
    instance: *mut std::ffi::c_void,
    p_create_info: *const VkWin32SurfaceCreateInfoKHR,
    p_allocator: *const std::ffi::c_void,
    p_surface: *mut u64,
) -> i32 {
    trace!("Vulkan: vkCreateWin32SurfaceKHR called instance={:p}", instance);
    if p_create_info.is_null() || p_surface.is_null() {
        return -1;
    }
    let handle = get_vulkan_handle();
    if handle.is_null() {
        return -1;
    }

    let hwnd = unsafe { (*p_create_info).hwnd };
    let x11_window = crate::platform::x11::hwnd_to_x11_window(hwnd).unwrap_or(0);
    let dpy = crate::platform::x11::x11_display().unwrap_or(std::ptr::null_mut());

    trace!("Vulkan: vkCreateWin32SurfaceKHR hwnd=0x{:x} x11_window=0x{:x} display={:p}", hwnd, x11_window, dpy);

    let xlib_info = VkXlibSurfaceCreateInfoKHR {
        s_type: 1000004000, // VK_STRUCTURE_TYPE_XLIB_SURFACE_CREATE_INFO_KHR
        p_next: std::ptr::null(),
        flags: 0,
        dpy: dpy.cast(),
        window: x11_window as usize,
    };

    type VkCreateXlibSurfaceKHRFn = unsafe extern "C" fn(
        *mut std::ffi::c_void,
        *const VkXlibSurfaceCreateInfoKHR,
        *const std::ffi::c_void,
        *mut u64,
    ) -> i32;

    let real_proc: Option<VkCreateXlibSurfaceKHRFn> = unsafe {
        let sym = CString::new("vkCreateXlibSurfaceKHR").unwrap();
        let ptr = libc::dlsym(handle, sym.as_ptr());
        if !ptr.is_null() {
            Some(std::mem::transmute(ptr))
        } else {
            None
        }
    };

    if let Some(f) = real_proc {
        let res = unsafe { f(instance, &xlib_info, p_allocator, p_surface) };
        trace!("Vulkan: vkCreateXlibSurfaceKHR returned result={} surface=0x{:x}", res, unsafe { *p_surface });
        res
    } else {
        trace!("Vulkan: vkCreateXlibSurfaceKHR failed - host symbol missing");
        -7
    }
}

pub extern "win64" fn vkGetPhysicalDeviceWin32PresentationSupportKHR(
    _physical_device: *mut std::ffi::c_void,
    _queue_family_index: u32,
) -> u32 {
    trace!("Vulkan: vkGetPhysicalDeviceWin32PresentationSupportKHR called");
    1
}

pub extern "win64" fn vkEnumerateInstanceExtensionProperties(
    p_layer_name: *const libc::c_char,
    p_property_count: *mut u32,
    p_properties: *mut VkExtensionProperties,
) -> i32 {
    trace!("Vulkan: vkEnumerateInstanceExtensionProperties called");
    let handle = get_vulkan_handle();
    if handle.is_null() {
        return -1;
    }
    type VkEnumExtFn =
        unsafe extern "C" fn(*const libc::c_char, *mut u32, *mut VkExtensionProperties) -> i32;
    let real_proc: Option<VkEnumExtFn> = unsafe {
        let sym = CString::new("vkEnumerateInstanceExtensionProperties").unwrap();
        let ptr = libc::dlsym(handle, sym.as_ptr());
        if !ptr.is_null() {
            Some(std::mem::transmute(ptr))
        } else {
            None
        }
    };
    if let Some(f) = real_proc {
        let res = unsafe { f(p_layer_name, p_property_count, p_properties) };
        if res == 0 && !p_property_count.is_null() {
            unsafe {
                let count = *p_property_count;
                if !p_properties.is_null() {
                    for i in 0..count as usize {
                        let prop = &mut *p_properties.add(i);
                        let name_cstr = CStr::from_ptr(prop.extension_name.as_ptr());
                        if name_cstr.to_str().unwrap_or_default() == "VK_KHR_xlib_surface" {
                            let win32_name = b"VK_KHR_win32_surface\0";
                            std::ptr::copy_nonoverlapping(
                                win32_name.as_ptr().cast(),
                                prop.extension_name.as_mut_ptr(),
                                win32_name.len(),
                            );
                        }
                    }
                }
            }
        }
        trace!("Vulkan: vkEnumerateInstanceExtensionProperties returned res={} count={}", res, unsafe { p_property_count.as_ref().copied().unwrap_or(0) });
        res
    } else {
        -1
    }
}

pub extern "win64" fn vkCreateInstance(
    p_create_info: *const VkInstanceCreateInfo,
    p_allocator: *const std::ffi::c_void,
    p_instance: *mut *mut std::ffi::c_void,
) -> i32 {
    trace!("Vulkan: vkCreateInstance called");
    if p_create_info.is_null() {
        return -1;
    }

    let mut new_ext_ptrs: Vec<*const libc::c_char> = Vec::new();
    let mut cstrings: Vec<CString> = Vec::new();

    unsafe {
        let count = (*p_create_info).enabled_extension_count as usize;
        let names_ptr = (*p_create_info).pp_enabled_extension_names;
        if !names_ptr.is_null() {
            for i in 0..count {
                let ptr = *names_ptr.add(i);
                if !ptr.is_null() {
                    let s = CStr::from_ptr(ptr).to_str().unwrap_or_default();
                    if s == "VK_KHR_win32_surface" {
                        info!("Vulkan: Translating VK_KHR_win32_surface -> VK_KHR_xlib_surface");
                        let cs = CString::new("VK_KHR_xlib_surface").unwrap();
                        new_ext_ptrs.push(cs.as_ptr());
                        cstrings.push(cs);
                    } else {
                        new_ext_ptrs.push(ptr);
                    }
                }
            }
        }
    }

    let mut modified_info = unsafe {
        VkInstanceCreateInfo {
            s_type: (*p_create_info).s_type,
            p_next: (*p_create_info).p_next,
            flags: (*p_create_info).flags,
            p_application_info: (*p_create_info).p_application_info,
            enabled_layer_count: (*p_create_info).enabled_layer_count,
            pp_enabled_layer_names: (*p_create_info).pp_enabled_layer_names,
            enabled_extension_count: (*p_create_info).enabled_extension_count,
            pp_enabled_extension_names: (*p_create_info).pp_enabled_extension_names,
        }
    };

    if !new_ext_ptrs.is_empty() {
        modified_info.enabled_extension_count = new_ext_ptrs.len() as u32;
        modified_info.pp_enabled_extension_names = new_ext_ptrs.as_ptr();
    }

    let handle = get_vulkan_handle();
    if handle.is_null() {
        return -1;
    }
    type VkCreateInstanceFn = unsafe extern "C" fn(
        *const VkInstanceCreateInfo,
        *const std::ffi::c_void,
        *mut *mut std::ffi::c_void,
    ) -> i32;
    let real_proc: Option<VkCreateInstanceFn> = unsafe {
        let sym = CString::new("vkCreateInstance").unwrap();
        let ptr = libc::dlsym(handle, sym.as_ptr());
        if !ptr.is_null() {
            Some(std::mem::transmute(ptr))
        } else {
            None
        }
    };
    if let Some(f) = real_proc {
        let res = unsafe { f(&modified_info, p_allocator, p_instance) };
        info!("Vulkan: vkCreateInstance returned res={} instance={:p}", res, unsafe { p_instance.as_ref().copied().unwrap_or(std::ptr::null_mut()) });
        let _ = cstrings;
        res
    } else {
        -1
    }
}

pub extern "win64" fn vkEnumeratePhysicalDevices(
    instance: *mut std::ffi::c_void,
    p_physical_device_count: *mut u32,
    p_physical_devices: *mut *mut std::ffi::c_void,
) -> i32 {
    info!("Vulkan: vkEnumeratePhysicalDevices instance={:p}", instance);
    let handle = get_vulkan_handle();
    if handle.is_null() { return -1; }
    type VkEnumPhysDevFn = unsafe extern "C" fn(*mut std::ffi::c_void, *mut u32, *mut *mut std::ffi::c_void) -> i32;
    let real_proc: Option<VkEnumPhysDevFn> = unsafe {
        let sym = CString::new("vkEnumeratePhysicalDevices").unwrap();
        let ptr = libc::dlsym(handle, sym.as_ptr());
        if !ptr.is_null() { Some(std::mem::transmute(ptr)) } else { None }
    };
    if let Some(f) = real_proc {
        let res = unsafe { f(instance, p_physical_device_count, p_physical_devices) };
        info!("Vulkan: vkEnumeratePhysicalDevices res={} count={}", res, unsafe { p_physical_device_count.as_ref().copied().unwrap_or(0) });
        res
    } else {
        -1
    }
}

pub extern "win64" fn vkEnumerateDeviceExtensionProperties(
    physical_device: *mut std::ffi::c_void,
    p_layer_name: *const libc::c_char,
    p_property_count: *mut u32,
    p_properties: *mut std::ffi::c_void,
) -> i32 {
    info!("Vulkan: vkEnumerateDeviceExtensionProperties phys_dev={:p}", physical_device);
    let handle = get_vulkan_handle();
    if handle.is_null() { return -1; }
    type VkEnumDevExtFn = unsafe extern "C" fn(*mut std::ffi::c_void, *const libc::c_char, *mut u32, *mut std::ffi::c_void) -> i32;
    let real_proc: Option<VkEnumDevExtFn> = unsafe {
        let sym = CString::new("vkEnumerateDeviceExtensionProperties").unwrap();
        let ptr = libc::dlsym(handle, sym.as_ptr());
        if !ptr.is_null() { Some(std::mem::transmute(ptr)) } else { None }
    };
    if let Some(f) = real_proc {
        let res = unsafe { f(physical_device, p_layer_name, p_property_count, p_properties) };
        info!("Vulkan: vkEnumerateDeviceExtensionProperties res={} count={}", res, unsafe { p_property_count.as_ref().copied().unwrap_or(0) });
        res
    } else {
        -1
    }
}

// Trampoline stubs generated via macro
vulkan_stub!(vkGetPhysicalDeviceProperties, p1: usize, p2: usize);
vulkan_stub!(vkGetPhysicalDeviceProperties2, p1: usize, p2: usize);
vulkan_stub!(vkGetPhysicalDeviceProperties2KHR, p1: usize, p2: usize);
vulkan_stub!(vkGetPhysicalDeviceFeatures, p1: usize, p2: usize);
vulkan_stub!(vkGetPhysicalDeviceFeatures2, p1: usize, p2: usize);
vulkan_stub!(vkGetPhysicalDeviceFeatures2KHR, p1: usize, p2: usize);
vulkan_stub!(vkGetPhysicalDeviceMemoryProperties, p1: usize, p2: usize);
vulkan_stub!(vkGetPhysicalDeviceMemoryProperties2, p1: usize, p2: usize);
vulkan_stub!(vkGetPhysicalDeviceMemoryProperties2KHR, p1: usize, p2: usize);
vulkan_stub!(vkGetPhysicalDeviceQueueFamilyProperties, p1: usize, p2: usize, p3: usize);
vulkan_stub!(vkGetPhysicalDeviceQueueFamilyProperties2, p1: usize, p2: usize, p3: usize);
vulkan_stub!(vkGetPhysicalDeviceQueueFamilyProperties2KHR, p1: usize, p2: usize, p3: usize);
vulkan_stub!(vkGetPhysicalDeviceFormatProperties, p1: usize, p2: u32, p3: usize);
vulkan_stub!(vkGetPhysicalDeviceFormatProperties2, p1: usize, p2: u32, p3: usize);
vulkan_stub!(vkGetPhysicalDeviceFormatProperties2KHR, p1: usize, p2: u32, p3: usize);
vulkan_stub!(vkGetPhysicalDeviceImageFormatProperties, p1: usize, p2: u32, p3: u32, p4: u32, p5: u32, p6: u32, p7: usize);
vulkan_stub!(vkGetPhysicalDeviceImageFormatProperties2, p1: usize, p2: usize, p3: usize);
vulkan_stub!(vkGetPhysicalDeviceImageFormatProperties2KHR, p1: usize, p2: usize, p3: usize);
vulkan_stub!(vkGetPhysicalDeviceSparseImageFormatProperties, p1: usize, p2: u32, p3: u32, p4: u32, p5: u32, p6: u32, p7: usize, p8: usize);
vulkan_stub!(vkGetPhysicalDeviceSparseImageFormatProperties2, p1: usize, p2: usize, p3: usize, p4: usize);
vulkan_stub!(vkGetPhysicalDeviceExternalSemaphoreProperties, p1: usize, p2: usize, p3: usize);
vulkan_stub!(vkGetPhysicalDeviceExternalSemaphorePropertiesKHR, p1: usize, p2: usize, p3: usize);

vulkan_stub!(vkGetPhysicalDeviceSurfaceSupportKHR, p1: usize, p2: u32, p3: u64, p4: usize);
vulkan_stub!(vkGetPhysicalDeviceSurfaceCapabilitiesKHR, p1: usize, p2: u64, p3: usize);
vulkan_stub!(vkGetPhysicalDeviceSurfaceCapabilities2KHR, p1: usize, p2: usize, p3: usize);
vulkan_stub!(vkGetPhysicalDeviceSurfaceFormatsKHR, p1: usize, p2: u64, p3: usize, p4: usize);
vulkan_stub!(vkGetPhysicalDeviceSurfaceFormats2KHR, p1: usize, p2: usize, p3: usize, p4: usize);
vulkan_stub!(vkGetPhysicalDeviceSurfacePresentModesKHR, p1: usize, p2: u64, p3: usize, p4: usize);
vulkan_stub!(vkGetPhysicalDeviceSurfacePresentModes2EXT, p1: usize, p2: usize, p3: usize, p4: usize);

vulkan_stub!(vkCreateDevice, p1: usize, p2: usize, p3: usize, p4: usize);
vulkan_stub!(vkGetDeviceQueue, p1: usize, p2: u32, p3: u32, p4: usize);
vulkan_stub!(vkGetDeviceQueue2, p1: usize, p2: usize, p3: usize);

vulkan_stub!(vkDestroyInstance, p1: usize, p2: usize);
vulkan_stub!(vkDestroyDevice, p1: usize, p2: usize);
vulkan_stub!(vkDestroySurfaceKHR, p1: usize, p2: u64, p3: usize);

vulkan_stub!(vkCreateBuffer, p1: usize, p2: usize, p3: usize, p4: usize);
vulkan_stub!(vkDestroyBuffer, p1: usize, p2: u64, p3: usize);
vulkan_stub!(vkCreateImage, p1: usize, p2: usize, p3: usize, p4: usize);
vulkan_stub!(vkDestroyImage, p1: usize, p2: u64, p3: usize);
vulkan_stub!(vkCreateImageView, p1: usize, p2: usize, p3: usize, p4: usize);
vulkan_stub!(vkDestroyImageView, p1: usize, p2: u64, p3: usize);
vulkan_stub!(vkCreateShaderModule, p1: usize, p2: usize, p3: usize, p4: usize);
vulkan_stub!(vkDestroyShaderModule, p1: usize, p2: u64, p3: usize);
vulkan_stub!(vkCreatePipelineLayout, p1: usize, p2: usize, p3: usize, p4: usize);
vulkan_stub!(vkDestroyPipelineLayout, p1: usize, p2: u64, p3: usize);
vulkan_stub!(vkCreateGraphicsPipelines, p1: usize, p2: u64, p3: u32, p4: usize, p5: usize, p6: usize);
vulkan_stub!(vkCreateComputePipelines, p1: usize, p2: u64, p3: u32, p4: usize, p5: usize, p6: usize);
vulkan_stub!(vkDestroyPipeline, p1: usize, p2: u64, p3: usize);

vulkan_stub!(vkAllocateMemory, p1: usize, p2: usize, p3: usize, p4: usize);
vulkan_stub!(vkFreeMemory, p1: usize, p2: u64, p3: usize);
vulkan_stub!(vkMapMemory, p1: usize, p2: u64, p3: u64, p4: u64, p5: u32, p6: usize);
vulkan_stub!(vkUnmapMemory, p1: usize, p2: u64);
vulkan_stub!(vkFlushMappedMemoryRanges, p1: usize, p2: u32, p3: usize);
vulkan_stub!(vkInvalidateMappedMemoryRanges, p1: usize, p2: u32, p3: usize);

vulkan_stub!(vkCreateCommandPool, p1: usize, p2: usize, p3: usize, p4: usize);
vulkan_stub!(vkDestroyCommandPool, p1: usize, p2: u64, p3: usize);
vulkan_stub!(vkResetCommandPool, p1: usize, p2: u64, p3: u32);
vulkan_stub!(vkAllocateCommandBuffers, p1: usize, p2: usize, p3: usize);
vulkan_stub!(vkFreeCommandBuffers, p1: usize, p2: u64, p3: u32, p4: usize);
vulkan_stub!(vkBeginCommandBuffer, p1: usize, p2: usize);
vulkan_stub!(vkEndCommandBuffer, p1: usize);
vulkan_stub!(vkResetCommandBuffer, p1: usize, p2: u32);

vulkan_stub!(vkCreateSemaphore, p1: usize, p2: usize, p3: usize, p4: usize);
vulkan_stub!(vkDestroySemaphore, p1: usize, p2: u64, p3: usize);
vulkan_stub!(vkCreateFence, p1: usize, p2: usize, p3: usize, p4: usize);
vulkan_stub!(vkDestroyFence, p1: usize, p2: u64, p3: usize);
vulkan_stub!(vkResetFences, p1: usize, p2: u32, p3: usize);
vulkan_stub!(vkWaitForFences, p1: usize, p2: u32, p3: usize, p4: u32, p5: u64);
vulkan_stub!(vkGetFenceStatus, p1: usize, p2: u64);

vulkan_stub!(vkCreateSwapchainKHR, p1: usize, p2: usize, p3: usize, p4: usize);
vulkan_stub!(vkDestroySwapchainKHR, p1: usize, p2: u64, p3: usize);
vulkan_stub!(vkGetSwapchainImagesKHR, p1: usize, p2: u64, p3: usize, p4: usize);
vulkan_stub!(vkAcquireNextImageKHR, p1: usize, p2: u64, p3: u64, p4: u64, p5: u64, p6: usize);
vulkan_stub!(vkQueuePresentKHR, p1: usize, p2: usize);
vulkan_stub!(vkQueueSubmit, p1: usize, p2: u32, p3: usize, p4: u64);
vulkan_stub!(vkQueueWaitIdle, p1: usize);
vulkan_stub!(vkDeviceWaitIdle, p1: usize);

pub extern "win64" fn vkGetInstanceProcAddr(
    instance: usize,
    name: *const libc::c_char,
) -> usize {
    if name.is_null() { return 0; }
    let name_c = unsafe { std::ffi::CStr::from_ptr(name) };
    let name_str = name_c.to_str().unwrap_or("");
    tracing::trace!("vkGetInstanceProcAddr(instance={:#x}, name={})", instance, name_str);

    let handle = crate::win32::vulkan::get_vulkan_handle();
    if handle.is_null() { return 0; }

    type RealGetProc = unsafe extern "C" fn(usize, *const libc::c_char) -> usize;
    let real_get_proc: Option<RealGetProc> = unsafe {
        let sym = std::ffi::CStr::from_bytes_with_nul_unchecked(b"vkGetInstanceProcAddr");
        let ptr = libc::dlsym(handle, sym.as_ptr());
        if !ptr.is_null() { Some(std::mem::transmute(ptr)) } else { None }
    };
    
    let real_ptr = if let Some(f) = real_get_proc {
        unsafe { f(instance, name) }
    } else {
        0
    };
    
    if real_ptr == 0 {
        tracing::warn!("vkGetInstanceProcAddr real function NOT FOUND for {}", name_str);
        // We still might fall back to our manual overrides
    } else {
        crate::win32::vulkan::vk_thunks::register_real_pointer(name_str, real_ptr);
    }

    match name_str {
        "vkGetInstanceProcAddr" => return vkGetInstanceProcAddr as usize,
        "vkGetDeviceProcAddr" => return vkGetDeviceProcAddr as usize,
        "vkCreateInstance" => return vkCreateInstance as usize,
        "vkEnumerateInstanceExtensionProperties" => return vkEnumerateInstanceExtensionProperties as usize,
        "vkEnumeratePhysicalDevices" => return vkEnumeratePhysicalDevices as usize,
        "vkEnumerateDeviceExtensionProperties" => return vkEnumerateDeviceExtensionProperties as usize,
        "vkGetPhysicalDeviceWin32PresentationSupportKHR" => return vkGetPhysicalDeviceWin32PresentationSupportKHR as usize,
        "vkCreateWin32SurfaceKHR" => return vkCreateWin32SurfaceKHR as usize,
        _ => {}
    }

    let exports = AUTO_EXPORTS.get_or_init(|| vk_thunks::get_auto_exports());
    if let Some(&ptr) = exports.get(name_str) {
        return ptr;
    }

    tracing::warn!("vkGetInstanceProcAddr: Unhandled Vulkan function: {}", name_str);
    0
}

pub extern "win64" fn vkGetDeviceProcAddr(
    device: usize,
    name: *const libc::c_char,
) -> usize {
    if name.is_null() { return 0; }
    let name_c = unsafe { std::ffi::CStr::from_ptr(name) };
    let name_str = name_c.to_str().unwrap_or("");
    tracing::trace!("vkGetDeviceProcAddr(device={:#x}, name={})", device, name_str);

    let handle = crate::win32::vulkan::get_vulkan_handle();
    if handle.is_null() { return 0; }

    type RealGetProc = unsafe extern "C" fn(usize, *const libc::c_char) -> usize;
    let real_get_proc: Option<RealGetProc> = unsafe {
        let sym = std::ffi::CStr::from_bytes_with_nul_unchecked(b"vkGetDeviceProcAddr");
        let ptr = libc::dlsym(handle, sym.as_ptr());
        if !ptr.is_null() { Some(std::mem::transmute(ptr)) } else { None }
    };
    
    let real_ptr = if let Some(f) = real_get_proc {
        unsafe { f(device, name) }
    } else {
        0
    };
    
    if real_ptr == 0 {
        tracing::warn!("vkGetDeviceProcAddr real function NOT FOUND for {}", name_str);
    } else {
        crate::win32::vulkan::vk_thunks::register_real_pointer(name_str, real_ptr);
    }

    match name_str {
        "vkGetDeviceProcAddr" => return vkGetDeviceProcAddr as usize,
        _ => {}
    }

    let exports = AUTO_EXPORTS.get_or_init(|| vk_thunks::get_auto_exports());
    if let Some(&ptr) = exports.get(name_str) {
        return ptr;
    }

    tracing::warn!("vkGetDeviceProcAddr: Unhandled Vulkan function: {}", name_str);
    0
}

static AUTO_EXPORTS: std::sync::OnceLock<std::collections::HashMap<&'static str, usize>> = std::sync::OnceLock::new();

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = vk_thunks::get_auto_exports();
    exports.insert("vkGetInstanceProcAddr", vkGetInstanceProcAddr as usize);
    exports.insert("vkGetDeviceProcAddr", vkGetDeviceProcAddr as usize);
    exports.insert("vkCreateInstance", vkCreateInstance as usize);
    exports.insert(
        "vkEnumerateInstanceExtensionProperties",
        vkEnumerateInstanceExtensionProperties as usize,
    );
    exports.insert("vkEnumeratePhysicalDevices", vkEnumeratePhysicalDevices as usize);
    exports.insert("vkEnumerateDeviceExtensionProperties", vkEnumerateDeviceExtensionProperties as usize);
    exports.insert("vkCreateDevice", vkCreateDevice as usize);
    exports.insert("vkCreateWin32SurfaceKHR", vkCreateWin32SurfaceKHR as usize);
    exports.insert(
        "vkGetPhysicalDeviceWin32PresentationSupportKHR",
        vkGetPhysicalDeviceWin32PresentationSupportKHR as usize,
    );

    exports
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This is intentionally opt-in because it requires a working host Vulkan
    /// ICD.  It exercises the Win64-to-System-V bridge instead of merely
    /// checking that libvulkan can be loaded.
    #[test]
    #[ignore = "requires a host Vulkan ICD"]
    fn host_vulkan_instance_and_adapter_enumeration_work_through_bridge() {
        let create_info = VkInstanceCreateInfo {
            s_type: 1, // VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO
            p_next: std::ptr::null(),
            flags: 0,
            p_application_info: std::ptr::null(),
            enabled_layer_count: 0,
            pp_enabled_layer_names: std::ptr::null(),
            enabled_extension_count: 0,
            pp_enabled_extension_names: std::ptr::null(),
        };
        let mut instance = std::ptr::null_mut();

        assert_eq!(
            vkCreateInstance(&create_info, std::ptr::null(), &mut instance),
            0,
            "host Vulkan rejected instance creation"
        );
        assert!(!instance.is_null());

        let mut physical_device_count = 0u32;
        assert_eq!(vkEnumeratePhysicalDevices(instance, &mut physical_device_count, std::ptr::null_mut()), 0);
        assert!(physical_device_count > 0);

        vkDestroyInstance(instance as usize, 0);
    }

    #[test]
    #[ignore = "requires an X11 display and a host Vulkan ICD"]
    fn win32_surface_extension_is_translated_to_a_real_xlib_surface() {
        let mut extension_count = 0u32;
        assert_eq!(
            vkEnumerateInstanceExtensionProperties(
                std::ptr::null(),
                &mut extension_count,
                std::ptr::null_mut(),
            ),
            0
        );
        let mut extensions: Vec<VkExtensionProperties> =
            (0..extension_count).map(|_| unsafe { std::mem::zeroed() }).collect();
        assert_eq!(
            vkEnumerateInstanceExtensionProperties(
                std::ptr::null(),
                &mut extension_count,
                extensions.as_mut_ptr(),
            ),
            0
        );
        assert!(extensions.iter().any(|property| unsafe {
            CStr::from_ptr(property.extension_name.as_ptr())
                .to_bytes() == b"VK_KHR_win32_surface"
        }));

        let extension = CString::new("VK_KHR_win32_surface").expect("static extension name");
        let extension_names = [extension.as_ptr()];
        let create_info = VkInstanceCreateInfo {
            s_type: 1,
            p_next: std::ptr::null(),
            flags: 0,
            p_application_info: std::ptr::null(),
            enabled_layer_count: 0,
            pp_enabled_layer_names: std::ptr::null(),
            enabled_extension_count: extension_names.len() as u32,
            pp_enabled_extension_names: extension_names.as_ptr(),
        };
        let mut instance = std::ptr::null_mut();
        assert_eq!(vkCreateInstance(&create_info, std::ptr::null(), &mut instance), 0);

        let Some(hwnd) = crate::platform::x11::create_x11_window("TuxExe Vulkan smoke", 0, 0, 64, 64) else {
            // This opt-in smoke test is also useful on a host with a Vulkan
            // ICD but no X11 access (for example, a sandboxed CI shell).
            vkDestroyInstance(instance as usize, 0);
            eprintln!("skipping Xlib surface creation: no usable X11 display");
            return;
        };
        let create_surface_info = VkWin32SurfaceCreateInfoKHR {
            s_type: 1000009000, // VK_STRUCTURE_TYPE_WIN32_SURFACE_CREATE_INFO_KHR
            p_next: std::ptr::null(),
            flags: 0,
            hinstance: 0,
            hwnd,
        };
        let mut surface = 0u64;
        assert_eq!(
            vkCreateWin32SurfaceKHR(
                instance,
                &create_surface_info,
                std::ptr::null(),
                &mut surface,
            ),
            0
        );
        assert_ne!(surface, 0);

        vkDestroySurfaceKHR(instance as usize, surface, 0);
        vkDestroyInstance(instance as usize, 0);
    }
}
