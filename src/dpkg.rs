//! Query dpkg for the package (and source package) that ships a file, plus its
//! installed version. Everything is best-effort: on non-dpkg systems, or when
//! the file is not shipped by any package, the caller simply gets `None`.
//!
//! We keep a tiny cache keyed by path so a backtrace with 30 frames from the
//! same shared library only runs `dpkg` twice.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

#[derive(Debug, Clone, Default)]
pub struct PackageInfo {
    pub package: Option<String>,
    pub package_version: Option<String>,
    pub source_package: Option<String>,
    pub source_version: Option<String>,
}

pub struct Dpkg {
    cache: Mutex<HashMap<String, PackageInfo>>,
}

impl Dpkg {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Look up a path in dpkg, caching the result. Absent, unowned, or dpkg-
    /// less systems yield an all-`None` `PackageInfo` -- lookup is best-effort.
    pub fn lookup(&self, path: &Path) -> PackageInfo {
        let key = path.to_string_lossy().into_owned();
        let mut cache = self.cache.lock().unwrap();
        cache
            .entry(key.clone())
            .or_insert_with(|| query(&key).unwrap_or_default())
            .clone()
    }
}

impl Default for Dpkg {
    fn default() -> Self {
        Self::new()
    }
}

fn query(path: &str) -> Option<PackageInfo> {
    let pkg = dpkg_owner(path)?;
    let show = dpkg_show(&pkg);
    let pkg_ver = show.as_ref().and_then(|s| s.version.clone());
    let source_field = show.as_ref().and_then(|s| s.source.clone());
    let split_version = show.as_ref().and_then(|s| s.source_version.clone());
    let (source_name, source_version) =
        parse_source(source_field.as_deref(), &pkg, pkg_ver.as_deref());
    // If dpkg gave us an explicit source:Version field, prefer it over what we
    // parsed out of the `foo (ver)` form.
    let source_version = split_version.or(source_version);
    Some(PackageInfo {
        package: Some(pkg),
        package_version: pkg_ver,
        source_package: source_name,
        source_version,
    })
}

#[derive(Default)]
struct ShowResult {
    version: Option<String>,
    source: Option<String>,
    source_version: Option<String>,
}

fn dpkg_owner(path: &str) -> Option<String> {
    // `dpkg -S` treats a bare word as a substring match against every file it
    // knows about, which produces nonsense hits (e.g. `yes` matching every
    // package whose filelist contains that trigraph). Only look up paths that
    // are actually paths.
    if !path.starts_with('/') {
        return None;
    }
    let out = Command::new("dpkg").arg("-S").arg(path).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Format is `pkg[:arch][, pkg2]: /path`. Take the first line, split on the
    // first colon before the space, then take the first colon-arch-separated
    // name.
    let first = stdout.lines().next()?;
    let (pkgs, _path) = first.split_once(": ")?;
    let name = pkgs
        .split(',')
        .next()?
        .trim()
        .split(':')
        .next()?
        .to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn dpkg_show(pkg: &str) -> Option<ShowResult> {
    let out = Command::new("dpkg-query")
        .arg("-W")
        .arg("-f=${Version}\t${source:Package}\t${source:Version}\n")
        .arg(pkg)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().next()?;
    let mut parts = line.split('\t');
    let version = parts.next().map(str::to_string).filter(|s| !s.is_empty());
    let source = parts.next().map(str::to_string).filter(|s| !s.is_empty());
    let source_version = parts.next().map(str::to_string).filter(|s| !s.is_empty());
    Some(ShowResult {
        version,
        source,
        source_version,
    })
}

/// Split `${source:Package}` output into (name, version). When empty, fall back
/// to the binary package name and version -- Debian policy is that a binary
/// package with no Source field is built from a source package of the same name
/// at the same version.
fn parse_source(
    src: Option<&str>,
    binary_pkg: &str,
    binary_ver: Option<&str>,
) -> (Option<String>, Option<String>) {
    let Some(src) = src else {
        return (Some(binary_pkg.to_string()), binary_ver.map(str::to_string));
    };
    if let Some((name, rest)) = src.split_once(" (") {
        let ver = rest.trim_end_matches(')').to_string();
        (Some(name.trim().to_string()), Some(ver))
    } else {
        (Some(src.trim().to_string()), binary_ver.map(str::to_string))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_source_defaults_to_binary_name() {
        let (n, v) = parse_source(None, "foo", Some("1.2-1"));
        assert_eq!(n.as_deref(), Some("foo"));
        assert_eq!(v.as_deref(), Some("1.2-1"));
    }

    #[test]
    fn parse_source_split() {
        let (n, v) = parse_source(Some("foo (1.0)"), "foo-bin", Some("2.0"));
        assert_eq!(n.as_deref(), Some("foo"));
        assert_eq!(v.as_deref(), Some("1.0"));
    }

    #[test]
    fn parse_source_no_version() {
        let (n, v) = parse_source(Some("libfoo"), "libfoo1", Some("3.4-5"));
        assert_eq!(n.as_deref(), Some("libfoo"));
        assert_eq!(v.as_deref(), Some("3.4-5"));
    }
}
