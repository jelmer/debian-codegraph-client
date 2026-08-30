//! `codegraph-symbolize`: symbolize a coredump and open it in the codegraph
//! web front-end.
//!
//! Given a core file (and optionally the executable that produced it), we run
//! gdb in batch mode to extract the backtrace, ask dpkg which packages own
//! each frame's binary, and pack the result into a JSON blob that lives in the
//! URL fragment of a codegraph.jelmer.uk symbolize link.

use anyhow::{Context, Result};
use cgcl::dpkg::Dpkg;
use cgcl::{Frame, OsInfo, Report};
use clap::Parser;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the core file to symbolize.
    core: PathBuf,

    /// Executable that produced the core. Optional: gdb will pick it up from
    /// the core's NT_FILE notes when available.
    #[arg(long, short = 'e')]
    executable: Option<PathBuf>,

    /// Base URL of the codegraph web front-end.
    #[arg(long, default_value = "https://codegraph.jelmer.uk")]
    base_url: String,

    /// Print the encoded JSON payload only (no URL wrapper). Useful for
    /// piping into other tooling.
    #[arg(long)]
    payload_only: bool,

    /// Print the raw (uncompressed, unencoded) JSON to stderr for debugging.
    #[arg(long)]
    dump_json: bool,

    /// Do not enrich frames with dpkg package information.
    #[arg(long)]
    no_dpkg: bool,

    /// Open the resulting URL in the user's browser via xdg-open.
    #[arg(long)]
    open: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let gdb = cgcl::gdb::analyze(&args.core, args.executable.as_deref())
        .context("gdb analysis failed")?;

    let mut report = Report::new();
    report.hostname = hostname();
    report.kernel = kernel_release();
    report.os = os_info();
    // Prefer whatever the caller told us, then fall back to gdb's argv[0].
    // If it's a bare name (no slash), resolve it against PATH so downstream
    // `dpkg -S` sees a real file path.
    report.executable = args
        .executable
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .or_else(|| gdb.executable.clone())
        .map(|e| resolve_executable(&e));
    report.command_line = gdb.command_line;
    report.signal = gdb.signal;
    report.signal_name = gdb.signal_name;

    let dpkg = if args.no_dpkg {
        None
    } else {
        Some(Dpkg::new())
    };

    for raw in gdb.frames {
        let mut frame = Frame {
            index: raw.index,
            address: raw.address,
            function: raw.function,
            file: raw.file,
            line: raw.line,
            column: None,
            binary: raw.binary,
            build_id: None,
            package: None,
            package_version: None,
            source_package: None,
            source_version: None,
            source_rel_path: None,
        };
        if let Some(bin) = frame.binary.as_deref().or(report.executable.as_deref()) {
            if let Some(dpkg) = &dpkg {
                let info = dpkg.lookup(Path::new(bin));
                frame.package = info.package;
                frame.package_version = info.package_version;
                frame.source_package = info.source_package;
                frame.source_version = info.source_version;
            }
            if frame.build_id.is_none() {
                frame.build_id = read_build_id(Path::new(bin));
            }
        }
        report.frames.push(frame);
    }

    if args.dump_json {
        let json = serde_json::to_string_pretty(&report)?;
        eprintln!("{json}");
    }

    if args.payload_only {
        println!("{}", report.encode()?);
    } else {
        let url = cgcl::symbolize_url(&args.base_url, &report)?;
        println!("{url}");
        if args.open {
            open_in_browser(&url)?;
        }
    }
    Ok(())
}

fn hostname() -> Option<String> {
    let u = rustix::system::uname();
    let s = u.nodename().to_string_lossy();
    if s.is_empty() {
        None
    } else {
        Some(s.into_owned())
    }
}

fn kernel_release() -> Option<String> {
    let u = rustix::system::uname();
    let s = u.release().to_string_lossy();
    if s.is_empty() {
        None
    } else {
        Some(s.into_owned())
    }
}

fn os_info() -> Option<OsInfo> {
    let text = std::fs::read_to_string("/etc/os-release").ok()?;
    let mut id = None;
    let mut version = None;
    let mut codename = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        // os-release values are shell-quoted; trim matching quotes but don't
        // try to interpret escapes -- the fields we care about don't use them.
        let v = v.trim_matches('"').trim_matches('\'').to_string();
        match k {
            "ID" => id = Some(v),
            "VERSION_ID" => version = Some(v),
            "VERSION_CODENAME" => codename = Some(v),
            _ => {}
        }
    }
    Some(OsInfo {
        id: id.unwrap_or_else(|| "unknown".into()),
        version,
        codename,
    })
}

/// Read the GNU build-id (hex) from an ELF `.note.gnu.build-id` section, using
/// readelf to avoid pulling in a full ELF parser for what is a diagnostic-only
/// field.
fn read_build_id(path: &Path) -> Option<String> {
    let out = std::process::Command::new("readelf")
        .arg("-n")
        .arg(path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Build ID: ") {
            let id = rest.trim().to_string();
            if !id.is_empty() {
                return Some(id);
            }
        }
    }
    None
}

/// If `exe` is already a path, return it unchanged so we preserve the caller's
/// intent (canonicalising would follow symlinks like `/usr/bin/python3` ->
/// `/usr/bin/python3.11` and retarget dpkg lookups). If it's a bare name, walk
/// `$PATH` for a match. Returns the original string when no resolution is
/// available -- downstream code treats it as best-effort.
fn resolve_executable(exe: &str) -> String {
    if exe.contains('/') {
        return exe.to_string();
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(exe);
            if candidate.is_file() {
                return candidate.to_string_lossy().into_owned();
            }
        }
    }
    exe.to_string()
}

fn open_in_browser(url: &str) -> Result<()> {
    let status = std::process::Command::new("xdg-open").arg(url).status()?;
    if !status.success() {
        anyhow::bail!("xdg-open exited with {status}");
    }
    Ok(())
}
