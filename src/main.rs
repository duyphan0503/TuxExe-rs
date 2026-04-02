use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::info;

use tuxexe_rs::exceptions::signals::install_signal_handlers;
use tuxexe_rs::exceptions::unwind::register_runtime_function_table;
use tuxexe_rs::pe_loader::imports::enumerate_imports;
use tuxexe_rs::pe_loader::mapper::map_pe;
use tuxexe_rs::pe_loader::parser::{Machine, ParsedPe};
use tuxexe_rs::pe_loader::relocations::apply_relocations;
use tuxexe_rs::threading::tls::{invoke_process_attach_callbacks, register_tls_callbacks};
use tuxexe_rs::utils::handle::init_global_table;
use tuxexe_rs::win32::kernel32::process::set_main_image_base;

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
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialise tracing with the requested level.
    let level_filter = cli.log_level.parse::<tracing::Level>().unwrap_or(tracing::Level::INFO);

    let subscriber = tracing_subscriber::fmt()
        .with_max_level(level_filter)
        .with_target(false)
        .with_thread_ids(false)
        .compact()
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .context("Failed to set tracing subscriber")?;

    match cli.command {
        Commands::Run { exe, args } => {
            info!(exe = %exe.display(), ?args, "Preparing to execute PE");

            if tuxexe_rs::wow64::try_delegate_x86_run(&exe, &args)
                .map_err(|error| anyhow::anyhow!("Failed x86 delegation backend: {error}"))?
            {
                info!(exe = %exe.display(), "Executed x86 binary via delegated backend");
                return Ok(());
            }

            init_global_table();

            // Phase 1: Load, map, relocate, enumerate imports.
            let mut pe = run_pe_loader(&exe)?;
            set_main_image_base(pe.mapped.base_addr());
            if pe.parsed.machine == Machine::X86 {
                tuxexe_rs::wow64::setup_wow64_context(pe.mapped.base_addr())
                    .map_err(|error| anyhow::anyhow!("Failed to setup WoW64 context: {error}"))?;
            } else {
                register_runtime_function_table(&pe.parsed, &pe.mapped)
                    .map_err(|error| anyhow::anyhow!("Failed to register unwind table: {error}"))?;
            }
            install_signal_handlers()
                .map_err(|error| anyhow::anyhow!("Failed to install signal handlers: {error}"))?;

            let _wow64_dll_mode_guard = (pe.parsed.machine == Machine::X86)
                .then(tuxexe_rs::dll_manager::search::enter_wow64_search_mode);

            // Resolve and patch imports
            tuxexe_rs::pe_loader::imports::resolve_imports(&mut pe.mapped, &pe.parsed, &pe.imports)
                .with_context(|| "Failed to resolve imports")?;

            // Apply memory protection
            pe.mapped
                .apply_protections(&pe.parsed)
                .with_context(|| "Failed to apply memory protections")?;

            register_tls_callbacks(&pe.parsed, &pe.mapped)
                .map_err(|error| anyhow::anyhow!("Failed to register TLS callbacks: {error}"))?;

            // Execute
            let entry_point_rva = pe.parsed.entry_point_rva as usize;
            if entry_point_rva == 0 {
                anyhow::bail!("PE has no entry point or it's statically linked as a DLL.");
            }

            let entry_point_addr = pe.mapped.base_addr() + entry_point_rva;
            info!(va = format_args!("0x{:x}", entry_point_addr), "Jumping to entry point");

            // Create thread execution block / environment manually or just jump straight to the entry point.
            // Some very basic things may break if the PE relies purely on FS/GS TEB structures without
            // the NT kernel properly backing them up.
            tuxexe_rs::threading::teb::setup_teb(pe.mapped.base_addr())
                .map_err(|e| anyhow::anyhow!("Failed to setup TEB: {}", e))?;

            invoke_process_attach_callbacks();

            // Note: If the target is a 64-bit Windows PE, its entry point uses the Win64 ABI, but typically takes no args.
            // On Windows 64-bit, the entry point for EXEs actually doesn't have a standardized ABI signature
            // typically `void mainCRTStartup()` -> no args.
            unsafe {
                let entry_fn: extern "win64" fn() = std::mem::transmute(entry_point_addr);
                entry_fn(); // JUMP!
            }

            info!("Execution finished successfully");
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
