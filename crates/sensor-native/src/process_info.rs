/// Synchronously reads /proc/{pid}/status to extract PPID.
/// This is intentionally sync — it's called from the ring buffer poll path
/// and must be fast. Falls back to 0 on any error.
pub fn read_ppid(pid: u32) -> u32 {
    let path = format!("/proc/{}/status", pid);
    let Ok(content) = std::fs::read_to_string(&path) else {
        return 0;
    };
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("PPid:\t") {
            return rest.trim().parse().unwrap_or(0);
        }
    }
    0
}

/// Reads the full executable path from /proc/{pid}/exe symlink.
/// Falls back to the comm name on error.
pub fn read_exe_path(pid: u32) -> Option<String> {
    let path = format!("/proc/{}/exe", pid);
    std::fs::read_link(&path)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}
