pub mod tunnel;
pub mod killswitch;
pub mod reconnect;

// The packet loop is platform-split: the Linux/Unix implementation works
// on raw file descriptors, while the Windows implementation drives the
// WinTun session API (no file descriptor exists on Windows).
#[cfg(unix)]
pub mod packet_loop;

#[cfg(target_os = "windows")]
pub mod packet_loop_windows;

pub mod controller;
