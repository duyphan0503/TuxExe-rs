use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use tracing::{info, warn};

use tuxexe_rs::dll_manager::{resolve_export_status, ExportStatus};
use tuxexe_rs::exceptions::signals::install_signal_handlers;
use tuxexe_rs::exceptions::unwind::register_runtime_function_table;
use tuxexe_rs::pe_loader::imports::{enumerate_delay_imports, enumerate_imports, ImportKind};
use tuxexe_rs::pe_loader::mapper::map_pe;
use tuxexe_rs::pe_loader::parser::{Machine, ParsedPe};
use tuxexe_rs::pe_loader::relocations::apply_relocations;
use tuxexe_rs::threading::tls::{
    invoke_tls_callbacks_for, register_tls_callbacks, DLL_PROCESS_ATTACH,
};
use tuxexe_rs::utils::handle::init_global_table;
use tuxexe_rs::win32::kernel32::process::{
    set_guest_command_line, set_main_image_base, set_main_image_path,
};

/// TuxExe-rs — run Windows PE executables on Linux.
#[derive(Parser, Debug)]
#[command(name = "tuxexe")]
#[command(version, about = "A Rust-based Windows PE compatibility layer for Linux")]
#[command(long_about = None)]
struct Cli {
    /// Set logging level (error, warn, info, debug, trace)
    #[arg(short, long, default_value = "info", global = true)]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Execute a Windows .exe file
    Run {
        /// Target frame rate limit (0 for uncapped, or e.g. 60, 144, 240)
        #[arg(long, default_value = "0")]
        fps: u32,

        /// Path to the Windows PE executable
        #[arg(value_name = "EXE")]
        exe: PathBuf,

        /// Arguments to pass to the Windows executable
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Show information about a PE file without executing it
    Info {
        /// Path to the Windows PE executable or DLL
        #[arg(value_name = "PE_FILE")]
        file: PathBuf,
    },

    /// Show compatibility audit (implemented vs missing imports by DLL)
    Audit {
        /// Path to the Windows PE executable or DLL
        #[arg(value_name = "PE_FILE")]
        file: PathBuf,
    },

    /// Check and synchronize host fonts with virtual Windows C:\Windows\Fonts
    Fonts {
        /// Verbose list of all linked fonts
        #[arg(short, long)]
        verbose: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialise tracing with the requested level.
    let level_filter = match cli.log_level.to_lowercase().as_str() {
        "error" => tracing::level_filters::LevelFilter::ERROR,
        "warn" => tracing::level_filters::LevelFilter::WARN,
        "info" => tracing::level_filters::LevelFilter::INFO,
        "debug" => tracing::level_filters::LevelFilter::DEBUG,
        "trace" => tracing::level_filters::LevelFilter::TRACE,
        _ => tracing::level_filters::LevelFilter::INFO,
    };

    use tracing_subscriber::layer::SubscriberExt;

    let log_file =
        std::fs::OpenOptions::new().create(true).write(true).truncate(true).open("tuxexe.log").ok();

    let console_layer =
        tracing_subscriber::fmt::layer().with_target(false).with_thread_ids(false).compact();

    let registry = tracing_subscriber::registry().with(level_filter).with(console_layer);

    if let Some(file) = log_file {
        let file_layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_thread_ids(true)
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(file));
        tracing::subscriber::set_global_default(registry.with(file_layer))
            .context("Failed to set tracing subscriber")?;
    } else {
        tracing::subscriber::set_global_default(registry)
            .context("Failed to set tracing subscriber")?;
    }

    match cli.command {
        Commands::Fonts { verbose } => {
            let drives = tuxexe_rs::filesystem::drives::DriveMap::default();
            let report = tuxexe_rs::filesystem::fonts::init_fonts_directory(&drives)
                .map_err(|e| anyhow::anyhow!("Failed to initialize fonts: {e}"))?;

            println!("TuxExe-rs Windows Fonts Virtualization Report");
            println!("============================================");
            println!("Virtual Fonts Directory: {}", report.fonts_dir.display());
            println!("Total Linked Host Fonts: {}", report.linked_count);
            println!("Standard Windows Aliases: {}", report.alias_count);
            println!();

            if let Some(health) = report.health {
                println!("Font Categories Status:");
                println!(
                    "  - Latin (Arial, Times, Courier, etc.): {}",
                    if health.has_latin_fonts { "Installed" } else { "Missing" }
                );
                println!(
                    "  - CJK (Japanese / Chinese / Korean):   {}",
                    if health.has_cjk_fonts { "Installed" } else { "Missing" }
                );
                println!(
                    "    * Japanese Fonts:                   {}",
                    if health.has_japanese_fonts { "Yes" } else { "No" }
                );
                println!(
                    "    * Chinese Fonts:                    {}",
                    if health.has_chinese_fonts { "Yes" } else { "No" }
                );
                println!();

                if !health.missing_recommendations.is_empty() {
                    println!("Recommendations for Missing Fonts:");
                    for rec in health.missing_recommendations {
                        println!("  - {rec}");
                    }
                    println!();
                } else {
                    println!("All essential font families (Latin + CJK) are healthy and available for games.");
                }
            }

            if verbose {
                println!("\nDiscovered Host Fonts in C:\\Windows\\Fonts:");
                if let Ok(entries) = std::fs::read_dir(&report.fonts_dir) {
                    let mut list: Vec<_> = entries
                        .flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect();
                    list.sort();
                    for name in list {
                        println!("  {name}");
                    }
                }
            }

            Ok(())
        }

        Commands::Run { fps, exe, args } => {
            let exe = std::fs::canonicalize(&exe)
                .with_context(|| format!("Failed to resolve executable path: {}", exe.display()))?;
            std::thread::Builder::new()
                .name("tuxexe-runner".to_string())
                .stack_size(32 * 1024 * 1024)
                .spawn(move || -> anyhow::Result<()> {
                    info!(exe = %exe.display(), fps, ?args, "Preparing to execute PE");

                    if fps > 0 {
                        std::env::set_var("TUXEXE_FPS", fps.to_string());
                        std::env::set_var("DXVK_FRAME_RATE", fps.to_string());
                    }
                    if std::env::var("__GL_SYNC_TO_VBLANK").is_err() {
                        std::env::set_var("__GL_SYNC_TO_VBLANK", if fps > 0 { "1" } else { "0" });
                    }
                    if std::env::var("vblank_mode").is_err() {
                        std::env::set_var("vblank_mode", if fps > 0 { "1" } else { "0" });
                    }

                    let drives = tuxexe_rs::filesystem::drives::DriveMap::default();
                    if let Ok(report) = tuxexe_rs::filesystem::fonts::init_fonts_directory(&drives)
                    {
                        info!(
                            linked_fonts = report.linked_count,
                            aliases = report.alias_count,
                            "Windows Fonts virtual directory synchronized"
                        );
                    }

                    tuxexe_rs::dll_manager::search::set_executable_directory(
                        exe.parent().map(PathBuf::from),
                    );
                    if let Some(parent) = exe.parent() {
                        std::env::set_current_dir(parent).with_context(|| {
                            format!("Failed to use game data directory: {}", parent.display())
                        })?;
                    }

                    // Set optimized DXVK and graphics performance variables if not overridden
                    if std::env::var("DXVK_ASYNC").is_err() {
                        std::env::set_var("DXVK_ASYNC", "1");
                    }
                    if std::env::var("DXVK_STATE_CACHE").is_err() {
                        std::env::set_var("DXVK_STATE_CACHE", "1");
                    }
                    if std::env::var("DXVK_HUD").is_err() {
                        std::env::set_var("DXVK_HUD", "fps,frametimes");
                    }
                    if std::env::var("DXVK_LOG_LEVEL").is_err() {
                        std::env::set_var("DXVK_LOG_LEVEL", "none");
                    }
                    if std::env::var("DXVK_CONFIG").is_err() {
                        std::env::set_var(
                            "DXVK_CONFIG",
                            tuxexe_rs::dxvk::runtime::build_dxvk_config(fps),
                        );
                    }

                    // Auto-select dedicated NVIDIA GPU if available for hardware-accelerated 3D
                    if std::path::Path::new("/usr/share/vulkan/icd.d/nvidia_icd.json").exists() {
                        if std::env::var("__NV_PRIME_RENDER_OFFLOAD").is_err() {
                            std::env::set_var("__NV_PRIME_RENDER_OFFLOAD", "1");
                        }
                        if std::env::var("__GLX_VENDOR_LIBRARY_NAME").is_err() {
                            std::env::set_var("__GLX_VENDOR_LIBRARY_NAME", "nvidia");
                        }
                        if std::env::var("__VK_LAYER_NV_optimus").is_err() {
                            std::env::set_var("__VK_LAYER_NV_optimus", "NVIDIA_only");
                        }
                        if std::env::var("VK_DRIVER_FILES").is_err() {
                            std::env::set_var(
                                "VK_DRIVER_FILES",
                                "/usr/share/vulkan/icd.d/nvidia_icd.json",
                            );
                        }
                    }

                    if let Some(warning) = tuxexe_rs::wow64::enforce_native_x86_backend() {
                        warn!("{warning}");
                        eprintln!("warning: {warning}");
                    }

                    // Initialize Windows environment variables
                    tuxexe_rs::win32::kernel32::env::init_windows_env_vars();
                    tuxexe_rs::win32::kernel32::system::init_kuser_shared_data();

                    init_global_table();

                    set_main_image_path(&exe);
                    set_guest_command_line(&exe, &args);

                    // Phase 1: Load, map, relocate, enumerate imports.
                    let mut pe = run_pe_loader(&exe)?;
                    set_main_image_base(pe.mapped.base_addr());
                    if pe.parsed.machine == Machine::X86 {
                        tuxexe_rs::wow64::setup_wow64_context(
                            pe.mapped.base_addr(),
                            pe.mapped.size(),
                        )
                        .map_err(|error| {
                            anyhow::anyhow!("Failed to setup WoW64 context: {error}")
                        })?;
                    } else {
                        register_runtime_function_table(&pe.parsed, &pe.mapped).map_err(
                            |error| anyhow::anyhow!("Failed to register unwind table: {error}"),
                        )?;
                    }

                    // Establish the main guest TEB/PEB before resolving dependencies.
                    // UnityPlayer.dll has static TLS; letting its loader initialize a
                    // placeholder TEB first creates a PEB with ImageBaseAddress == 0,
                    // which corrupts early Unity startup state.
                    if pe.parsed.machine != Machine::X86 {
                        tuxexe_rs::threading::teb::setup_teb(pe.mapped.base_addr())
                            .map_err(|error| anyhow::anyhow!("Failed to setup TEB: {error}"))?;
                    }

                    install_signal_handlers().map_err(|error| {
                        anyhow::anyhow!("Failed to install signal handlers: {error}")
                    })?;

                    let _wow64_dll_mode_guard = (pe.parsed.machine == Machine::X86)
                        .then(tuxexe_rs::dll_manager::search::enter_wow64_search_mode);

                    // Resolve and patch imports
                    tuxexe_rs::pe_loader::imports::resolve_imports(
                        &mut pe.mapped,
                        &pe.parsed,
                        &pe.imports,
                    )
                    .with_context(|| "Failed to resolve imports")?;

                    // Apply memory protection
                    pe.mapped
                        .apply_protections(&pe.parsed)
                        .with_context(|| "Failed to apply memory protections")?;

                    register_tls_callbacks(&pe.parsed, &pe.mapped).map_err(|error| {
                        anyhow::anyhow!("Failed to register TLS callbacks: {error}")
                    })?;

                    // Initialize static TLS
                    tuxexe_rs::threading::tls::initialize_static_tls(&pe.parsed, &mut pe.mapped)
                        .map_err(|error| {
                            anyhow::anyhow!("Failed to initialize static TLS: {error}")
                        })?;

                    // PE32 has a separate WoW64 execution contract. Never cast an x86
                    // entry point to the host x64 ABI: doing so corrupts the host
                    // stack/register state and turns an unsupported path into a
                    // process crash.
                    if pe.parsed.machine == Machine::X86 {
                        return tuxexe_rs::wow64::entry::execute_pe32_entry(
                            &pe.parsed,
                            pe.mapped.base_addr(),
                        )
                        .map_err(|error| anyhow::anyhow!(error));
                    }

                    invoke_tls_callbacks_for(&pe.parsed, &pe.mapped, DLL_PROCESS_ATTACH).map_err(
                        |error| {
                            anyhow::anyhow!("Failed to invoke main-image TLS callbacks: {error}")
                        },
                    )?;

                    // Execute PE64.
                    let entry_point_rva = pe.parsed.entry_point_rva as usize;
                    if entry_point_rva == 0 {
                        anyhow::bail!("PE has no entry point or it's statically linked as a DLL.");
                    }

                    let entry_point_addr = pe.mapped.base_addr() + entry_point_rva;
                    info!(va = format_args!("0x{:x}", entry_point_addr), "Jumping to entry point");

                    tuxexe_rs::runtime::guest_stack::invoke(entry_point_addr).map_err(|error| {
                        anyhow::anyhow!("Failed to execute PE64 entry: {error}")
                    })?;

                    info!("Execution finished successfully");
                    Ok(())
                })
                .map_err(|e| anyhow::anyhow!("Failed to spawn runner thread: {e}"))?
                .join()
                .map_err(|_| anyhow::anyhow!("Runner thread panicked"))??;
            Ok(())
        }

        Commands::Audit { file } => {
            info!(file = %file.display(), "Auditing PE import compatibility");
            run_compat_audit(&file)?;
            Ok(())
        }

        Commands::Info { file } => {
            info!(file = %file.display(), "Inspecting PE file");
            let pe = run_pe_loader(&file)?;

            println!("PE File: {}", file.display());
            println!("  Machine:      {}", pe.parsed.machine);
            println!("  PE64:         {}", pe.parsed.is_pe64);
            println!("  ImageBase:    0x{:x}", pe.parsed.image_base);
            println!(
                "  EntryPoint:   0x{:x} (RVA), 0x{:x} (preferred VA)",
                pe.parsed.entry_point_rva,
                pe.parsed.preferred_entry_point()
            );
            println!("  SizeOfImage:  0x{:x}", pe.parsed.size_of_image);
            println!("  Sections:");
            for sec in &pe.parsed.sections {
                println!(
                    "    {:<12} VA=0x{:08x}  VSize=0x{:06x}  RawSize=0x{:06x}  {}",
                    sec.name,
                    sec.virtual_address,
                    sec.virtual_size,
                    sec.raw_data_size,
                    sec.perm_str()
                );
            }
            println!(
                "  Relocations:  {} fixups applied (delta = {:#x})",
                pe.reloc_result.fixups_applied, pe.reloc_result.delta
            );
            println!(
                "  Imports:      {} functions from {} DLLs",
                pe.imports.total_imports(),
                pe.imports.dlls.len()
            );
            for dll in &pe.imports.dlls {
                let names: Vec<_> = pe.imports.for_dll(dll).map(|e| e.import.to_string()).collect();
                println!("    {dll}: {}", names.join(", "));
            }

            Ok(())
        }
    }
}

/// Result of the PE loading pipeline (parse → map → relocate → enumerate imports).
struct LoadedPe {
    parsed: ParsedPe,
    #[allow(dead_code)]
    mapped: tuxexe_rs::pe_loader::mapper::MappedImage,
    reloc_result: tuxexe_rs::pe_loader::relocations::RelocationResult,
    imports: tuxexe_rs::pe_loader::imports::ImportTable,
}

fn run_compat_audit(path: &std::path::Path) -> Result<()> {
    let pe = run_pe_loader(path)?;
    let delay_imports = enumerate_delay_imports(&pe.parsed, &pe.mapped)
        .with_context(|| "Failed to enumerate delay imports")?;

    let mut by_dll: BTreeMap<String, BTreeMap<String, ExportStatus>> = BTreeMap::new();

    let mut ingest = |dll: &str, import: &ImportKind| {
        let symbol = match import {
            ImportKind::ByName { name, .. } => name.clone(),
            ImportKind::ByOrdinal(ord) => format!("#{ord}"),
        };

        let status = resolve_export_status(dll, &symbol);
        by_dll
            .entry(dll.to_ascii_lowercase())
            .or_default()
            .entry(symbol)
            .and_modify(|existing| {
                if *existing == ExportStatus::Unsupported {
                    *existing = status;
                }
            })
            .or_insert(status);
    };

    for entry in &pe.imports.entries {
        ingest(&entry.dll, &entry.import);
    }
    for entry in &delay_imports.entries {
        ingest(&entry.dll, &entry.import);
    }

    let mut implemented_total = 0usize;
    let mut total = 0usize;
    for symbols in by_dll.values() {
        total += symbols.len();
        implemented_total +=
            symbols.values().filter(|status| **status == ExportStatus::Implemented).count();
    }
    let stub_total = by_dll
        .values()
        .flat_map(|symbols| symbols.values())
        .filter(|status| **status == ExportStatus::CompatibilityStub)
        .count();
    let unsupported_total = by_dll
        .values()
        .flat_map(|symbols| symbols.values())
        .filter(|status| **status == ExportStatus::Unsupported)
        .count();
    let percent =
        if total == 0 { 100.0 } else { (implemented_total as f64 / total as f64) * 100.0 };

    println!("Compatibility Audit: {}", path.display());
    println!(
        "Summary: implemented {implemented_total}/{total} ({percent:.1}%), compatibility stubs {stub_total}, unsupported {unsupported_total}"
    );
    println!(
        "(normal imports: {}, delay imports: {})",
        pe.imports.entries.len(),
        delay_imports.entries.len()
    );
    println!("By DLL:");

    for (dll, symbols) in &by_dll {
        let dll_impl =
            symbols.values().filter(|status| **status == ExportStatus::Implemented).count();
        let dll_stubs =
            symbols.values().filter(|status| **status == ExportStatus::CompatibilityStub).count();
        let dll_missing =
            symbols.values().filter(|status| **status == ExportStatus::Unsupported).count();
        println!("  {dll}: {dll_impl} implemented, {dll_stubs} compatibility stubs, {dll_missing} unsupported");

        if dll_missing > 0 {
            let missing = symbols
                .iter()
                .filter_map(|(name, status)| {
                    (*status == ExportStatus::Unsupported).then_some(name.as_str())
                })
                .take(12)
                .collect::<Vec<_>>();
            println!("    missing(sample): {}", missing.join(", "));
        }
    }

    let missing_dlls = by_dll
        .iter()
        .filter(|(_, symbols)| symbols.values().any(|status| *status == ExportStatus::Unsupported))
        .map(|(dll, _)| dll.clone())
        .collect::<BTreeSet<_>>();

    if !missing_dlls.is_empty() {
        println!(
            "\nPriority DLLs to implement next: {}",
            missing_dlls.into_iter().collect::<Vec<_>>().join(", ")
        );
    }

    Ok(())
}

/// Run the full PE loading pipeline.
fn run_pe_loader(path: &std::path::Path) -> Result<LoadedPe> {
    // 1. Parse
    let parsed = ParsedPe::from_file(path)
        .with_context(|| format!("Failed to parse PE: {}", path.display()))?;

    // 2. Map
    let mut mapped = map_pe(&parsed)
        .with_context(|| format!("Failed to map PE into memory: {}", path.display()))?;

    info!(
        base = format_args!("0x{:x}", mapped.base_addr()),
        at_preferred = mapped.at_preferred,
        "Image mapped"
    );

    // 3. Relocate
    let reloc_result = apply_relocations(&parsed, &mut mapped)
        .with_context(|| "Failed to apply base relocations")?;

    // 4. Enumerate imports
    let imports =
        enumerate_imports(&parsed, &mapped).with_context(|| "Failed to enumerate imports")?;

    Ok(LoadedPe { parsed, mapped, reloc_result, imports })
}
