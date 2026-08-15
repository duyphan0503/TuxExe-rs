#![allow(non_snake_case, dead_code, unused_variables)]

use std::collections::HashMap;
use std::sync::OnceLock;
use tracing::{debug, info};

static ENGLISH: &[u8] = b"english\0";
static US: &[u8] = b"US\0";
static PLAYER: &[u8] = b"Player\0";

static DUMMY_OBJECT: [usize; 64] = [0; 64];

extern "win64" fn ReturnDummyInterface() -> *const usize {
    DUMMY_OBJECT.as_ptr()
}

extern "win64" fn ReturnDummyInterface4(_a: usize, _b: usize, _c: usize, _d: usize) -> *const usize {
    DUMMY_OBJECT.as_ptr()
}

extern "win64" fn ReturnDummyInterface3(_a: usize, _b: usize, _c: usize) -> *const usize {
    DUMMY_OBJECT.as_ptr()
}

extern "win64" fn ReturnDummyInterface2(_a: usize, _b: usize) -> *const usize {
    DUMMY_OBJECT.as_ptr()
}

extern "win64" fn ReturnDummyInterface1(_a: usize) -> *const usize {
    DUMMY_OBJECT.as_ptr()
}

extern "win64" fn SteamAPI_Init() -> u32 {
    info!("SteamAPI_Init called -> returning 1 (success)");
    1
}

extern "win64" fn SteamAPI_InitFlat(_err_msg: *mut u8) -> i32 {
    info!("SteamAPI_InitFlat called -> returning 0 (k_ESteamAPIInitResult_OK)");
    0
}

extern "win64" fn SteamAPI_Shutdown() {
    info!("SteamAPI_Shutdown called");
}

extern "win64" fn SteamAPI_RestartAppIfNecessary(_app_id: u32) -> u32 {
    0
}

extern "win64" fn SteamAPI_ReleaseCurrentThreadMemory() {}

extern "win64" fn SteamAPI_RunCallbacks() {}

extern "win64" fn SteamAPI_IsSteamRunning() -> u32 {
    1
}

extern "win64" fn SteamAPI_GetHSteamUser() -> i32 {
    1
}

extern "win64" fn SteamAPI_GetHSteamPipe() -> i32 {
    1
}

// UGC / Workshop
extern "win64" fn SteamAPI_ISteamUGC_GetNumSubscribedItems(_instance: usize) -> u32 {
    0
}

extern "win64" fn SteamAPI_ISteamUGC_GetSubscribedItems(_instance: usize, _pvec: *mut u64, _max: u32) -> u32 {
    0
}

extern "win64" fn SteamAPI_ISteamUGC_GetItemInstallInfo(
    _instance: usize,
    _published_file_id: u64,
    _size_on_disk: *mut u64,
    _folder: *mut u8,
    _folder_size: u32,
    _timestamp: *mut u32,
) -> u32 {
    0
}

// Utils
extern "win64" fn SteamAPI_ISteamUtils_GetAppID(_instance: usize) -> u32 {
    2739590
}

extern "win64" fn SteamAPI_ISteamUtils_GetSteamUILanguage(_instance: usize) -> *const u8 {
    ENGLISH.as_ptr()
}

extern "win64" fn SteamAPI_ISteamUtils_GetIPCountry(_instance: usize) -> *const u8 {
    US.as_ptr()
}

extern "win64" fn SteamAPI_ISteamUtils_IsOverlayEnabled(_instance: usize) -> u32 {
    0
}

extern "win64" fn SteamAPI_ISteamUtils_IsSteamInBigPictureMode(_instance: usize) -> u32 {
    0
}

extern "win64" fn SteamAPI_ISteamUtils_IsSteamRunningOnSteamDeck(_instance: usize) -> u32 {
    0
}

extern "win64" fn SteamAPI_ISteamUtils_IsSteamRunningInVR(_instance: usize) -> u32 {
    0
}

extern "win64" fn SteamAPI_ISteamUtils_GetServerRealTime(_instance: usize) -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

extern "win64" fn SteamAPI_ISteamUtils_GetCurrentBatteryPower(_instance: usize) -> u8 {
    255
}

// User
extern "win64" fn SteamAPI_ISteamUser_GetSteamID(_instance: usize) -> u64 {
    76561198000000001
}

extern "win64" fn SteamAPI_ISteamUser_BLoggedOn(_instance: usize) -> u32 {
    1
}

extern "win64" fn SteamAPI_ISteamUser_GetPlayerSteamLevel(_instance: usize) -> i32 {
    10
}

extern "win64" fn SteamAPI_ISteamUser_GetHSteamUser(_instance: usize) -> i32 {
    1
}

// Apps
extern "win64" fn SteamAPI_ISteamApps_BIsSubscribed(_instance: usize) -> u32 {
    1
}

extern "win64" fn SteamAPI_ISteamApps_BIsSubscribedApp(_instance: usize, _app_id: u32) -> u32 {
    1
}

extern "win64" fn SteamAPI_ISteamApps_BIsDlcInstalled(_instance: usize, _app_id: u32) -> u32 {
    1
}

extern "win64" fn SteamAPI_ISteamApps_GetCurrentGameLanguage(_instance: usize) -> *const u8 {
    ENGLISH.as_ptr()
}

extern "win64" fn SteamAPI_ISteamApps_GetAvailableGameLanguages(_instance: usize) -> *const u8 {
    ENGLISH.as_ptr()
}

// Friends
extern "win64" fn SteamAPI_ISteamFriends_GetPersonaName(_instance: usize) -> *const u8 {
    PLAYER.as_ptr()
}

extern "win64" fn SteamAPI_ISteamFriends_GetPersonaState(_instance: usize) -> i32 {
    1 // Online
}

// UserStats
extern "win64" fn SteamAPI_ISteamUserStats_RequestCurrentStats(_instance: usize) -> u32 {
    1
}

extern "win64" fn SteamAPI_ISteamUserStats_GetAchievement(_instance: usize, _name: *const i8, pbAchieved: *mut u32) -> u32 {
    if !pbAchieved.is_null() {
        unsafe { *pbAchieved = 0; }
    }
    1
}

extern "win64" fn SteamAPI_ISteamUserStats_SetAchievement(_instance: usize, _name: *const i8) -> u32 {
    1
}

extern "win64" fn SteamAPI_ISteamUserStats_StoreStats(_instance: usize) -> u32 {
    1
}

extern "win64" fn SteamAPI_ISteamUserStats_ResetAllStats(_instance: usize, _achievements_too: u32) -> u32 {
    1
}

// SteamAPI_ManualDispatch
extern "win64" fn SteamAPI_ManualDispatch_Init() {}
extern "win64" fn SteamAPI_ManualDispatch_RunFrame(_h_steam_pipe: i32) {}
extern "win64" fn SteamAPI_ManualDispatch_GetNextCallback(_h_steam_pipe: i32, _p_callback_msg: *mut std::ffi::c_void) -> u32 {
    0 // false - no pending callbacks
}
extern "win64" fn SteamAPI_ManualDispatch_FreeLastCallback(_h_steam_pipe: i32) {}
extern "win64" fn SteamAPI_ManualDispatch_GetAPICallResult(
    _h_steam_pipe: i32,
    _h_steam_api_call: u64,
    _p_callback: *mut std::ffi::c_void,
    _cub_callback: i32,
    _i_callback_expected: i32,
    _pb_failed: *mut u32,
) -> u32 {
    0 // false
}

// Generic dummy fallback for any unhandled SteamAPI function
extern "win64" fn GenericSteamApiStub() -> usize {
    0
}

pub fn get_exports() -> HashMap<&'static str, usize> {
    let mut exports = HashMap::new();

    exports.insert("SteamAPI_Init", SteamAPI_Init as usize);
    exports.insert("SteamAPI_InitFlat", SteamAPI_InitFlat as usize);
    exports.insert("SteamAPI_Shutdown", SteamAPI_Shutdown as usize);
    exports.insert("SteamAPI_RestartAppIfNecessary", SteamAPI_RestartAppIfNecessary as usize);
    exports.insert("SteamAPI_ReleaseCurrentThreadMemory", SteamAPI_ReleaseCurrentThreadMemory as usize);
    exports.insert("SteamAPI_RunCallbacks", SteamAPI_RunCallbacks as usize);
    exports.insert("SteamAPI_IsSteamRunning", SteamAPI_IsSteamRunning as usize);
    exports.insert("SteamAPI_GetHSteamUser", SteamAPI_GetHSteamUser as usize);
    exports.insert("SteamAPI_GetHSteamPipe", SteamAPI_GetHSteamPipe as usize);

    // SteamAPI_ManualDispatch
    exports.insert("SteamAPI_ManualDispatch_Init", SteamAPI_ManualDispatch_Init as usize);
    exports.insert("SteamAPI_ManualDispatch_RunFrame", SteamAPI_ManualDispatch_RunFrame as usize);
    exports.insert("SteamAPI_ManualDispatch_GetNextCallback", SteamAPI_ManualDispatch_GetNextCallback as usize);
    exports.insert("SteamAPI_ManualDispatch_FreeLastCallback", SteamAPI_ManualDispatch_FreeLastCallback as usize);
    exports.insert("SteamAPI_ManualDispatch_GetAPICallResult", SteamAPI_ManualDispatch_GetAPICallResult as usize);

    exports.insert("SteamInternal_CreateInterface", ReturnDummyInterface as usize);
    exports.insert("SteamInternal_FindOrCreateUserInterface", ReturnDummyInterface2 as usize);
    exports.insert("SteamInternal_FindOrCreateGlobalInterface", ReturnDummyInterface as usize);
    exports.insert("SteamAPI_SetWarningMessageHook", GenericSteamApiStub as usize);
    exports.insert("SteamAPI_ISteamClient_SetWarningMessageHook", GenericSteamApiStub as usize);
    exports.insert("SteamAPI_ISteamUtils_SetWarningMessageHook", GenericSteamApiStub as usize);

    exports.insert("SteamClient", ReturnDummyInterface as usize);
    exports.insert("SteamAPI_SteamClient_v020", ReturnDummyInterface as usize);
    exports.insert("SteamUtils", ReturnDummyInterface as usize);
    exports.insert("SteamAPI_SteamUtils_v010", ReturnDummyInterface as usize);
    exports.insert("SteamUser", ReturnDummyInterface as usize);
    exports.insert("SteamAPI_SteamUser_v021", ReturnDummyInterface as usize);
    exports.insert("SteamUGC", ReturnDummyInterface as usize);
    exports.insert("SteamAPI_SteamUGC_v016", ReturnDummyInterface as usize);
    exports.insert("SteamApps", ReturnDummyInterface as usize);
    exports.insert("SteamAPI_SteamApps_v008", ReturnDummyInterface as usize);
    exports.insert("SteamUserStats", ReturnDummyInterface as usize);
    exports.insert("SteamAPI_SteamUserStats_v012", ReturnDummyInterface as usize);
    exports.insert("SteamFriends", ReturnDummyInterface as usize);
    exports.insert("SteamAPI_SteamFriends_v017", ReturnDummyInterface as usize);

    // SteamAPI_ISteamClient_Get* methods
    exports.insert("SteamAPI_ISteamClient_GetISteamUser", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamFriends", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamUtils", ReturnDummyInterface3 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamMatchmaking", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamMatchmakingServers", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamUserStats", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamApps", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamNetworking", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamRemoteStorage", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamScreenshots", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamHTTP", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamController", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamUGC", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamAppList", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamMusic", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamMusicRemote", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamHTMLSurface", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamInventory", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamVideo", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamParentalSettings", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamInput", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamParties", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamRemotePlay", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamNetworkingUtils", ReturnDummyInterface3 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamNetworkingSockets", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamNetworkingMessages", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamGameServer", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamGameServerStats", ReturnDummyInterface4 as usize);
    exports.insert("SteamAPI_ISteamClient_GetISteamGenericInterface", ReturnDummyInterface4 as usize);

    // SteamAPI_ISteamUGC
    exports.insert("SteamAPI_ISteamUGC_GetNumSubscribedItems", SteamAPI_ISteamUGC_GetNumSubscribedItems as usize);
    exports.insert("SteamAPI_ISteamUGC_GetSubscribedItems", SteamAPI_ISteamUGC_GetSubscribedItems as usize);
    exports.insert("SteamAPI_ISteamUGC_GetItemInstallInfo", SteamAPI_ISteamUGC_GetItemInstallInfo as usize);

    // SteamAPI_ISteamUtils
    exports.insert("SteamAPI_ISteamUtils_GetAppID", SteamAPI_ISteamUtils_GetAppID as usize);
    exports.insert("SteamAPI_ISteamUtils_GetSteamUILanguage", SteamAPI_ISteamUtils_GetSteamUILanguage as usize);
    exports.insert("SteamAPI_ISteamUtils_GetIPCountry", SteamAPI_ISteamUtils_GetIPCountry as usize);
    exports.insert("SteamAPI_ISteamUtils_IsOverlayEnabled", SteamAPI_ISteamUtils_IsOverlayEnabled as usize);
    exports.insert("SteamAPI_ISteamUtils_IsSteamInBigPictureMode", SteamAPI_ISteamUtils_IsSteamInBigPictureMode as usize);
    exports.insert("SteamAPI_ISteamUtils_IsSteamRunningOnSteamDeck", SteamAPI_ISteamUtils_IsSteamRunningOnSteamDeck as usize);
    exports.insert("SteamAPI_ISteamUtils_IsSteamRunningInVR", SteamAPI_ISteamUtils_IsSteamRunningInVR as usize);
    exports.insert("SteamAPI_ISteamUtils_GetServerRealTime", SteamAPI_ISteamUtils_GetServerRealTime as usize);
    exports.insert("SteamAPI_ISteamUtils_GetCurrentBatteryPower", SteamAPI_ISteamUtils_GetCurrentBatteryPower as usize);

    // SteamAPI_ISteamUser
    exports.insert("SteamAPI_ISteamUser_GetSteamID", SteamAPI_ISteamUser_GetSteamID as usize);
    exports.insert("SteamAPI_ISteamUser_BLoggedOn", SteamAPI_ISteamUser_BLoggedOn as usize);
    exports.insert("SteamAPI_ISteamUser_GetPlayerSteamLevel", SteamAPI_ISteamUser_GetPlayerSteamLevel as usize);
    exports.insert("SteamAPI_ISteamUser_GetHSteamUser", SteamAPI_ISteamUser_GetHSteamUser as usize);

    // SteamAPI_ISteamApps
    exports.insert("SteamAPI_ISteamApps_BIsSubscribed", SteamAPI_ISteamApps_BIsSubscribed as usize);
    exports.insert("SteamAPI_ISteamApps_BIsSubscribedApp", SteamAPI_ISteamApps_BIsSubscribedApp as usize);
    exports.insert("SteamAPI_ISteamApps_BIsDlcInstalled", SteamAPI_ISteamApps_BIsDlcInstalled as usize);
    exports.insert("SteamAPI_ISteamApps_GetCurrentGameLanguage", SteamAPI_ISteamApps_GetCurrentGameLanguage as usize);
    exports.insert("SteamAPI_ISteamApps_GetAvailableGameLanguages", SteamAPI_ISteamApps_GetAvailableGameLanguages as usize);

    // SteamAPI_ISteamFriends
    exports.insert("SteamAPI_ISteamFriends_GetPersonaName", SteamAPI_ISteamFriends_GetPersonaName as usize);
    exports.insert("SteamAPI_ISteamFriends_GetPersonaState", SteamAPI_ISteamFriends_GetPersonaState as usize);

    // SteamAPI_ISteamUserStats
    exports.insert("SteamAPI_ISteamUserStats_RequestCurrentStats", SteamAPI_ISteamUserStats_RequestCurrentStats as usize);
    exports.insert("SteamAPI_ISteamUserStats_GetAchievement", SteamAPI_ISteamUserStats_GetAchievement as usize);
    exports.insert("SteamAPI_ISteamUserStats_SetAchievement", SteamAPI_ISteamUserStats_SetAchievement as usize);
    exports.insert("SteamAPI_ISteamUserStats_StoreStats", SteamAPI_ISteamUserStats_StoreStats as usize);
    exports.insert("SteamAPI_ISteamUserStats_ResetAllStats", SteamAPI_ISteamUserStats_ResetAllStats as usize);

    exports
}

pub fn resolve_export(func_name: &str) -> Option<usize> {
    static EXPORTS: OnceLock<HashMap<&'static str, usize>> = OnceLock::new();
    let map = EXPORTS.get_or_init(get_exports);
    if let Some(&addr) = map.get(func_name) {
        return Some(addr);
    }
    let with_prefix = format!("SteamAPI_{func_name}");
    if let Some(&addr) = map.get(with_prefix.as_str()) {
        return Some(addr);
    }
    if let Some(stripped) = func_name.strip_prefix("SteamAPI_") {
        if let Some(&addr) = map.get(stripped) {
            return Some(addr);
        }
    }
    if func_name.contains("GetISteam") || func_name.contains("CreateInterface") || func_name.contains("Interface") {
        debug!("Unhandled steam_api64 interface getter '{}' -> returning ReturnDummyInterface", func_name);
        Some(ReturnDummyInterface as usize)
    } else {
        debug!("Unhandled steam_api64 function '{}' -> returning GenericSteamApiStub (0)", func_name);
        Some(GenericSteamApiStub as usize)
    }
}

