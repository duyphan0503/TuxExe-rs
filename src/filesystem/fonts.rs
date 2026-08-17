//! Font discovery, provisioning, and C:\Windows\Fonts virtualization.
//!
//! Automatically discovers installed fonts on Linux host systems (/usr/share/fonts,
//! ~/.local/share/fonts, ~/.fonts, fontconfig paths), sets up symlinks in the virtual
//! Windows `C:\Windows\Fonts` directory, provisions standard Windows font aliases
//! (Arial, Times New Roman, Courier New, Segoe UI, Tahoma, MS Gothic, SimSun, etc.),
//! and provides health checking / guidance for missing CJK or TrueType font packages.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

use crate::filesystem::drives::DriveMap;

/// Font category health status
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FontHealth {
    pub total_fonts_found: usize,
    pub has_latin_fonts: bool,
    pub has_cjk_fonts: bool,
    pub has_japanese_fonts: bool,
    pub has_chinese_fonts: bool,
    pub missing_recommendations: Vec<String>,
}

/// Result report from font synchronization
#[derive(Debug, Clone, Default)]
pub struct FontSyncReport {
    pub fonts_dir: PathBuf,
    pub linked_count: usize,
    pub alias_count: usize,
    pub health: Option<FontHealth>,
}

/// Standard Windows font alias mappings to candidate filenames in Linux
struct FontAliasTarget {
    alias_name: &'static str,
    candidates: &'static [&'static str],
}

const STANDARD_FONT_ALIASES: &[FontAliasTarget] = &[
    // Arial family
    FontAliasTarget {
        alias_name: "arial.ttf",
        candidates: &[
            "Arial.ttf",
            "arial.ttf",
            "LiberationSans-Regular.ttf",
            "DejaVuSans.ttf",
            "NotoSans-Regular.ttf",
            "FreeSans.ttf",
        ],
    },
    FontAliasTarget {
        alias_name: "arialbd.ttf",
        candidates: &[
            "Arial_Bold.ttf",
            "arialbd.ttf",
            "LiberationSans-Bold.ttf",
            "DejaVuSans-Bold.ttf",
            "NotoSans-Bold.ttf",
            "FreeSansBold.ttf",
        ],
    },
    FontAliasTarget {
        alias_name: "ariali.ttf",
        candidates: &[
            "Arial_Italic.ttf",
            "ariali.ttf",
            "LiberationSans-Italic.ttf",
            "DejaVuSans-Oblique.ttf",
            "NotoSans-Italic.ttf",
        ],
    },
    FontAliasTarget {
        alias_name: "arialbi.ttf",
        candidates: &[
            "Arial_Bold_Italic.ttf",
            "arialbi.ttf",
            "LiberationSans-BoldItalic.ttf",
            "DejaVuSans-BoldOblique.ttf",
            "NotoSans-BoldItalic.ttf",
        ],
    },
    // Times New Roman family
    FontAliasTarget {
        alias_name: "times.ttf",
        candidates: &[
            "Times_New_Roman.ttf",
            "times.ttf",
            "LiberationSerif-Regular.ttf",
            "DejaVuSerif.ttf",
            "NotoSerif-Regular.ttf",
            "FreeSerif.ttf",
        ],
    },
    FontAliasTarget {
        alias_name: "timesbd.ttf",
        candidates: &[
            "Times_New_Roman_Bold.ttf",
            "timesbd.ttf",
            "LiberationSerif-Bold.ttf",
            "DejaVuSerif-Bold.ttf",
            "NotoSerif-Bold.ttf",
        ],
    },
    // Courier New family
    FontAliasTarget {
        alias_name: "cour.ttf",
        candidates: &[
            "Courier_New.ttf",
            "cour.ttf",
            "LiberationMono-Regular.ttf",
            "DejaVuSansMono.ttf",
            "NotoSansMono-Regular.ttf",
            "FreeMono.ttf",
        ],
    },
    FontAliasTarget {
        alias_name: "courbd.ttf",
        candidates: &[
            "Courier_New_Bold.ttf",
            "courbd.ttf",
            "LiberationMono-Bold.ttf",
            "DejaVuSansMono-Bold.ttf",
            "NotoSansMono-Bold.ttf",
        ],
    },
    // Tahoma / Segoe UI / Verdana
    FontAliasTarget {
        alias_name: "tahoma.ttf",
        candidates: &[
            "tahoma.ttf",
            "Tahoma.ttf",
            "Verdana.ttf",
            "verdana.ttf",
            "LiberationSans-Regular.ttf",
            "NotoSans-Regular.ttf",
        ],
    },
    FontAliasTarget {
        alias_name: "segoeui.ttf",
        candidates: &[
            "segoeui.ttf",
            "SegoeUI.ttf",
            "Verdana.ttf",
            "LiberationSans-Regular.ttf",
            "NotoSans-Regular.ttf",
        ],
    },
    FontAliasTarget {
        alias_name: "verdana.ttf",
        candidates: &[
            "Verdana.ttf",
            "verdana.ttf",
            "DejaVuSans.ttf",
            "NotoSans-Regular.ttf",
        ],
    },
    // Japanese CJK Fonts (MS Gothic, Meiryo, Yu Gothic)
    FontAliasTarget {
        alias_name: "msgothic.ttc",
        candidates: &[
            "msgothic.ttc",
            "NotoSansCJK-Regular.ttc",
            "NotoSansJP-Regular.otf",
            "NotoSansJP-Regular.ttf",
            "TakaoPGothic.ttf",
            "ipagp.ttf",
            "ipag.ttf",
            "DroidSansFallbackFull.ttf",
        ],
    },
    FontAliasTarget {
        alias_name: "msmincho.ttc",
        candidates: &[
            "msmincho.ttc",
            "NotoSerifCJK-Regular.ttc",
            "NotoSerifJP-Regular.otf",
            "NotoSerifJP-Regular.ttf",
            "TakaoPMincho.ttf",
            "ipamp.ttf",
            "ipam.ttf",
            "DroidSansFallbackFull.ttf",
        ],
    },
    FontAliasTarget {
        alias_name: "meiryo.ttc",
        candidates: &[
            "meiryo.ttc",
            "NotoSansCJK-Regular.ttc",
            "NotoSansJP-Regular.otf",
            "TakaoPGothic.ttf",
            "DroidSansFallbackFull.ttf",
        ],
    },
    FontAliasTarget {
        alias_name: "yugoth.ttc",
        candidates: &[
            "yugoth.ttc",
            "NotoSansCJK-Regular.ttc",
            "NotoSansJP-Regular.otf",
            "TakaoPGothic.ttf",
        ],
    },
    // Chinese CJK Fonts (SimSun, SimHei, Microsoft YaHei)
    FontAliasTarget {
        alias_name: "simsun.ttc",
        candidates: &[
            "simsun.ttc",
            "NotoSansCJK-Regular.ttc",
            "NotoSansSC-Regular.otf",
            "NotoSerifCJK-Regular.ttc",
            "DroidSansFallbackFull.ttf",
            "wqy-zenhei.ttc",
            "wqy-microhei.ttc",
        ],
    },
    FontAliasTarget {
        alias_name: "simhei.ttf",
        candidates: &[
            "simhei.ttf",
            "NotoSansCJK-Bold.ttc",
            "NotoSansSC-Bold.otf",
            "DroidSansFallbackFull.ttf",
            "wqy-zenhei.ttc",
        ],
    },
    FontAliasTarget {
        alias_name: "msyh.ttc",
        candidates: &[
            "msyh.ttc",
            "NotoSansCJK-Regular.ttc",
            "NotoSansSC-Regular.otf",
            "DroidSansFallbackFull.ttf",
        ],
    },
    // Korean CJK Fonts (Gulim, Malgun Gothic, Batang)
    FontAliasTarget {
        alias_name: "gulim.ttc",
        candidates: &[
            "gulim.ttc",
            "NotoSansCJK-Regular.ttc",
            "NotoSansKR-Regular.otf",
            "UnDotum.ttf",
            "NanumGothic.ttf",
            "DroidSansFallbackFull.ttf",
        ],
    },
    FontAliasTarget {
        alias_name: "malgun.ttf",
        candidates: &[
            "malgun.ttf",
            "NotoSansCJK-Regular.ttc",
            "NotoSansKR-Regular.otf",
            "NanumGothic.ttf",
        ],
    },
];

/// Collect common host font search roots
pub fn host_font_directories() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    // Standard system font paths
    let standard = [
        "/usr/share/fonts",
        "/usr/local/share/fonts",
        "/opt/fonts",
        "/var/lib/snapd/desktop/fonts",
    ];
    for p in standard {
        let path = PathBuf::from(p);
        if path.is_dir() {
            dirs.push(path);
        }
    }

    // User-specific font paths
    if let Ok(home) = std::env::var("HOME") {
        let home_path = PathBuf::from(home);
        let user_fonts = [
            home_path.join(".local/share/fonts"),
            home_path.join(".fonts"),
        ];
        for path in user_fonts {
            if path.is_dir() {
                dirs.push(path);
            }
        }
    }

    dirs
}

/// Recursively find all font files (.ttf, .otf, .ttc, .fon) in given directories
pub fn discover_host_font_files(search_dirs: &[PathBuf]) -> BTreeMap<String, PathBuf> {
    let mut found = BTreeMap::new();

    for dir in search_dirs {
        scan_dir_for_fonts(dir, &mut found, 0, 10);
    }

    found
}

fn scan_dir_for_fonts(
    dir: &Path,
    results: &mut BTreeMap<String, PathBuf>,
    depth: usize,
    max_depth: usize,
) {
    if depth > max_depth {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_dir_for_fonts(&path, results, depth + 1, max_depth);
        } else if is_font_file(&path) {
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                results.insert(file_name.to_string(), path);
            }
        }
    }
}

fn is_font_file(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        matches!(
            ext.to_ascii_lowercase().as_str(),
            "ttf" | "otf" | "ttc" | "fon" | "woff" | "woff2"
        )
    } else {
        false
    }
}

/// Initialize and populate `C:\Windows\Fonts` in the virtual drive layout.
pub fn init_fonts_directory(drives: &DriveMap) -> Result<FontSyncReport, String> {
    let drive_c = drives
        .resolve('C')
        .ok_or_else(|| "Drive C: is not configured in DriveMap".to_string())?;

    let windows_dir = drive_c.join("windows");
    let fonts_dir = windows_dir.join("Fonts");
    let system32_dir = windows_dir.join("System32");

    // Ensure directory hierarchy exists
    fs::create_dir_all(&fonts_dir)
        .map_err(|e| format!("Failed to create fonts directory {}: {e}", fonts_dir.display()))?;
    let _ = fs::create_dir_all(&system32_dir);

    // Discover all fonts on host system
    let search_roots = host_font_directories();
    let discovered = discover_host_font_files(&search_roots);

    let mut report = FontSyncReport {
        fonts_dir: fonts_dir.clone(),
        linked_count: 0,
        alias_count: 0,
        health: None,
    };

    // Create symlinks for all discovered font files
    for (file_name, host_path) in &discovered {
        let dest = fonts_dir.join(file_name);
        if !dest.exists() {
            #[cfg(unix)]
            {
                let _ = std::os::unix::fs::symlink(host_path, &dest);
            }
            #[cfg(not(unix))]
            {
                let _ = fs::copy(host_path, &dest);
            }
        }

        // Also create lowercased symlink for case-insensitive lookup
        let lower_name = file_name.to_ascii_lowercase();
        if lower_name != *file_name {
            let lower_dest = fonts_dir.join(&lower_name);
            if !lower_dest.exists() {
                #[cfg(unix)]
                {
                    let _ = std::os::unix::fs::symlink(host_path, &lower_dest);
                }
                #[cfg(not(unix))]
                {
                    let _ = fs::copy(host_path, &lower_dest);
                }
            }
        }
        report.linked_count += 1;
    }

    // Provision standard Windows aliases
    for alias in STANDARD_FONT_ALIASES {
        let alias_dest = fonts_dir.join(alias.alias_name);
        if alias_dest.exists() {
            continue;
        }

        // Search candidate list
        for candidate in alias.candidates {
            if let Some(host_path) = discovered.get(*candidate) {
                #[cfg(unix)]
                {
                    let _ = std::os::unix::fs::symlink(host_path, &alias_dest);
                }
                #[cfg(not(unix))]
                {
                    let _ = fs::copy(host_path, &alias_dest);
                }
                report.alias_count += 1;
                debug!(alias = alias.alias_name, target = %host_path.display(), "Linked font alias");
                break;
            }
        }
    }

    // Evaluate health
    let health = evaluate_font_health(&discovered);
    if !health.has_cjk_fonts || !health.has_latin_fonts {
        for rec in &health.missing_recommendations {
            warn!("{rec}");
        }
    }
    report.health = Some(health);

    info!(
        fonts_dir = %fonts_dir.display(),
        linked_fonts = report.linked_count,
        aliases = report.alias_count,
        "Initialized Windows Fonts virtualization"
    );

    Ok(report)
}

/// Check system font health and generate actionable installation recommendations
pub fn evaluate_font_health(discovered: &BTreeMap<String, PathBuf>) -> FontHealth {
    let mut has_latin = false;
    let mut has_cjk = false;
    let mut has_japanese = false;
    let mut has_chinese = false;

    let cjk_indicators = [
        "notosanscjk",
        "notoserifcjk",
        "notosansjp",
        "notoserifjp",
        "notosanssc",
        "notosanskr",
        "notosanstc",
        "droidsansfallback",
        "takao",
        "ipag",
        "ipam",
        "wqy",
        "uming",
        "ukai",
        "msgothic",
        "msmincho",
        "meiryo",
        "simsun",
        "simhei",
    ];

    let latin_indicators = [
        "arial",
        "liberation",
        "dejavu",
        "notosans",
        "times",
        "verdana",
        "courier",
        "freesans",
    ];

    for name in discovered.keys() {
        let lower = name.to_ascii_lowercase();
        if latin_indicators.iter().any(|k| lower.contains(k)) {
            has_latin = true;
        }
        if cjk_indicators.iter().any(|k| lower.contains(k)) {
            has_cjk = true;
            if lower.contains("jp") || lower.contains("takao") || lower.contains("ipa") || lower.contains("msgothic") || lower.contains("meiryo") || lower.contains("cjk") {
                has_japanese = true;
            }
            if lower.contains("sc") || lower.contains("tc") || lower.contains("wqy") || lower.contains("simsun") || lower.contains("simhei") || lower.contains("cjk") {
                has_chinese = true;
            }
        }
    }

    let mut missing_recommendations = Vec::new();

    if !has_latin {
        missing_recommendations.push(
            "Notice: Basic TrueType fonts not found. For best compatibility, install: `sudo apt install fonts-liberation ttf-mscorefonts-installer` (or `fonts-dejavu-core`)".to_string()
        );
    }

    if !has_cjk {
        missing_recommendations.push(
            "Notice: CJK (Japanese/Chinese/Korean) fonts not found. Games using East Asian characters may display missing text or boxes. Install: `sudo apt install fonts-noto-cjk fonts-ipafont-gothic`".to_string()
        );
    }

    FontHealth {
        total_fonts_found: discovered.len(),
        has_latin_fonts: has_latin,
        has_cjk_fonts: has_cjk,
        has_japanese_fonts: has_japanese,
        has_chinese_fonts: has_chinese,
        missing_recommendations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn discovers_and_links_fonts() {
        let temp = tempdir().expect("tempdir");
        let prefix = temp.path().join(".tuxexe");
        let drives = DriveMap::new_with_prefix(prefix);

        let report = init_fonts_directory(&drives).expect("init fonts");
        assert!(report.fonts_dir.is_dir());
        assert!(report.health.is_some());
    }

    #[test]
    fn evaluates_font_health_accurately() {
        let mut map = BTreeMap::new();
        map.insert("LiberationSans-Regular.ttf".to_string(), PathBuf::from("/usr/share/fonts/LiberationSans-Regular.ttf"));
        map.insert("NotoSansCJK-Regular.ttc".to_string(), PathBuf::from("/usr/share/fonts/NotoSansCJK-Regular.ttc"));

        let health = evaluate_font_health(&map);
        assert!(health.has_latin_fonts);
        assert!(health.has_cjk_fonts);
        assert!(health.has_japanese_fonts);
        assert!(health.has_chinese_fonts);
        assert!(health.missing_recommendations.is_empty());
    }
}
