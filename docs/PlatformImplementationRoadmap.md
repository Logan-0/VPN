# VPN Platform Implementation Roadmap

**Status**: Tasks 71-76 require platform-specific testing environments  
**Target**: Complete macOS and Windows platform handlers with validation

---

## Task 71: macOS Platform Handler Implementation

**Objective**: Implement actual macOS platform handler with root checks, tool verification, and pf handling.

### Current State
- `src/platform/macos.rs` exists with stub implementation
- `MacOSPlatform::new()` returns `Ok(Self)` without validation
- Killswitch has pf rule implementation in `src/core/killswitch.rs` (lines 264-322)

### Required Implementation

```rust
// In src/platform/macos.rs - MacOSPlatform::new()
pub fn new() -> Result<Self> {
    // 1. Check for root privileges
    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("macOS platform handler requires root privileges (run with sudo)");
    }
    
    // 2. Verify ifconfig is available
    Command::new("ifconfig")
        .arg("-v")
        .output()
        .context("ifconfig command not found (required for IP configuration)")?;
    
    // 3. Verify route command is available
    Command::new("route")
        .arg("-h")
        .output()
        .context("route command not found (required for routing configuration)")?;
    
    // 4. Check pf (packet filter) availability
    Command::new("pfctl")
        .arg("-s")
        .arg("info")
        .output()
        .context("pfctl command not found (required for firewall rules)")?;
    
    tracing::info!("macOS platform handler initialized with root privileges");
    Ok(Self)
}
```

### Implementation Steps

1. Add `libc` crate dependency for `geteuid()` check
2. Implement root privilege verification
3. Add tool availability checks (ifconfig, route, pfctl)
4. Implement `create_tun()` method:
   - Create utun device using system calls or `tun` crate
   - Assign IP address via ifconfig
   - Set MTU to 1420
   - Configure routing via route command
5. Implement `cleanup()` method:
   - Remove routes
   - Bring interface down
   - Destroy utun device

### Testing Requirements

- Run on macOS 10.13+ (High Sierra or later)
- Test with and without sudo
- Verify ifconfig/route/pfctl availability detection
- Test utun device creation and cleanup
- Verify routing table changes

### Acceptance Criteria

- [PENDING] Root privilege check works correctly
- [PENDING] Tool availability checks detect missing commands
- [PENDING] utun device creation succeeds on macOS
- [PENDING] IP address assignment works
- [PENDING] Routing configuration is correct
- [PENDING] Cleanup removes all routes and destroys device

---

## Task 72: Windows Path Validation on Real Windows Hosts

**Objective**: Validate Windows implementation on actual Windows systems with runtime smoke tests.

### Current State
- `src/platform/windows.rs` has full implementation
- Uses `wintun` crate for adapter creation
- Uses `netsh` for IP and routing configuration
- Killswitch uses netsh for firewall rules

### Validation Checklist

1. **Administrator Privilege Check**
   - Verify code detects when not running as Administrator
   - Test error message is clear and actionable

2. **WinTun Driver Detection**
   - Test with WinTun installed via MSI
   - Test with wintun.dll bundled in executable directory
   - Test error handling when WinTun is not available

3. **Adapter Creation**
   - Verify adapter creation succeeds
   - Test adapter reuse on reconnect
   - Verify adapter cleanup on disconnect

4. **netsh Command Execution**
   - Test IP address assignment via netsh
   - Test MTU configuration
   - Test route addition/removal
   - Verify error handling for netsh failures

5. **Routing Configuration**
   - Verify half-default routes are added correctly
   - Test VPN server bypass route
   - Verify routes are removed on cleanup

### Testing Requirements

- Windows 10 or Windows 11
- Administrator privileges
- WireGuard server for end-to-end testing
- Network connectivity to test routes

### Acceptance Criteria

- [PENDING] Administrator check works correctly
- [PENDING] WinTun driver loading succeeds
- [PENDING] Adapter creation and reuse works
- [PENDING] netsh commands execute without errors
- [PENDING] Routes are added and removed correctly
- [PENDING] No orphaned adapters or routes after cleanup

---

## Task 73: Bundle and Validate `wintun.dll` in Release Artifacts

**Objective**: Ensure wintun.dll is properly bundled with Windows releases.

### Current Implementation

In `src/platform/windows.rs`:
```rust
pub fn new() -> Result<Self> {
    unsafe { wintun::load() }
        .map_err(|e| anyhow!("Failed to load wintun.dll: {}. Bundle wintun.dll alongside the executable.", e))?;
    // ...
}
```

### Required Changes

1. **Build Script (`build.rs`)**
   - Add logic to copy wintun.dll to output directory
   - Verify wintun.dll exists before building
   - Generate error if wintun.dll is missing

2. **Release Packaging**
   - Include wintun.dll in Windows release artifacts
   - Document wintun.dll requirement in README
   - Provide instructions for obtaining wintun.dll

3. **Runtime Validation**
   - Verify wintun.dll is in the same directory as executable
   - Check DLL version compatibility
   - Provide clear error message if DLL is missing

### Implementation Steps

1. Create `build.rs` in VPN project root:
   ```rust
   fn main() {
       // Copy wintun.dll to output directory
       let wintun_path = "vendor/wintun.dll";
       if std::path::Path::new(wintun_path).exists() {
           std::fs::copy(wintun_path, "wintun.dll")
               .expect("Failed to copy wintun.dll");
       }
   }
   ```

2. Update `Cargo.toml` to include build script:
   ```toml
   [build]
   build = "build.rs"
   ```

3. Add wintun.dll to release artifacts

### Testing Requirements

- Build on Windows with wintun.dll present
- Build on Windows with wintun.dll missing (should fail)
- Verify wintun.dll is included in release zip
- Test executable runs with bundled wintun.dll

### Acceptance Criteria

- [PENDING] build.rs copies wintun.dll correctly
- [PENDING] Build fails if wintun.dll is missing
- [PENDING] Release artifacts include wintun.dll
- [PENDING] Executable finds wintun.dll at runtime

---

## Task 74: Verify `netsh` Quoting Behavior for Spaces/Unicode Paths

**Objective**: Ensure netsh commands handle paths with spaces and Unicode characters correctly.

### Current Implementation

In `src/platform/windows.rs`:
```rust
fn run_netsh(args: &[&str]) -> Result<()> {
    let output = Command::new("netsh")
        .args(args)
        .output()
        .context("Failed to execute netsh command")?;
    // ...
}
```

### Issues to Address

1. **Spaces in Paths**
   - netsh may require quoting for paths with spaces
   - Test with adapter names containing spaces
   - Test with interface names containing spaces

2. **Unicode Characters**
   - netsh may not handle Unicode properly
   - Test with Unicode characters in paths
   - Verify error handling for unsupported characters

3. **Special Characters**
   - Test with quotes, backslashes, etc.
   - Verify escaping is correct
   - Test with various character encodings

### Implementation Steps

1. Add helper function for proper netsh argument quoting:
   ```rust
   fn quote_netsh_arg(arg: &str) -> String {
       if arg.contains(' ') || arg.contains('"') {
           format!("\"{}\"", arg.replace('"', "\\\""))
       } else {
           arg.to_string()
       }
   }
   ```

2. Update `run_netsh()` to use quoting helper

3. Add tests for various path formats

### Testing Requirements

- Test with adapter name: "My VPN Adapter"
- Test with paths containing Unicode: "C:\Users\Ñoño\..."
- Test with special characters: "adapter-name_123"
- Test with very long paths (>260 characters)

### Acceptance Criteria

- [PENDING] Spaces in paths are handled correctly
- [PENDING] Unicode characters are handled correctly
- [PENDING] Special characters are escaped properly
- [PENDING] Long paths work correctly
- [PENDING] All netsh commands execute without quoting errors

---

## Task 75: Validate WinTun Adapter Cleanup After Crash Scenarios

**Objective**: Ensure WinTun adapters are properly cleaned up even after application crashes.

### Current Implementation

In `src/platform/windows.rs`:
```rust
pub fn cleanup(&mut self) -> Result<()> {
    self.session = None;
    // Remove routes
    // Drop adapter
    Ok(())
}
```

### Crash Scenarios to Test

1. **Immediate Crash During Connection**
   - Kill process while adapter is being created
   - Verify adapter is not left in broken state
   - Verify routes are cleaned up

2. **Crash During Packet Loop**
   - Kill process while VPN is active
   - Verify adapter is still accessible
   - Verify routes can be removed manually

3. **Crash During Cleanup**
   - Kill process during cleanup
   - Verify adapter can be reused on restart
   - Verify no orphaned routes remain

4. **Multiple Crashes**
   - Crash and restart multiple times
   - Verify no duplicate adapters
   - Verify no orphaned routes accumulate

### Implementation Steps

1. Add cleanup verification function:
   ```rust
   fn verify_cleanup() -> Result<()> {
       // Check for orphaned adapters
       // Check for orphaned routes
       // Report any cleanup issues
   }
   ```

2. Add adapter reuse logic:
   - Detect existing adapter from previous crash
   - Reuse or clean up as appropriate
   - Log all cleanup actions

3. Add tests for crash scenarios

### Testing Requirements

- Windows 10 or Windows 11
- Administrator privileges
- Ability to kill process forcefully
- Network monitoring tools to verify cleanup

### Acceptance Criteria

- [PENDING] Adapters are reusable after crash
- [PENDING] Routes are cleaned up after crash
- [PENDING] No orphaned adapters accumulate
- [PENDING] No orphaned routes accumulate
- [PENDING] Cleanup verification works correctly

---

## Task 76: End-to-End Windows TUN Read/Write Smoke Test

**Objective**: Run complete end-to-end test with real WireGuard server on Windows.

### Test Setup

1. **WireGuard Server**
   - Set up WireGuard server on Linux or cloud VM
   - Generate server and client keys
   - Configure server to accept connections

2. **Windows Test Machine**
   - Install VPN application
   - Configure with WireGuard server endpoint
   - Ensure network connectivity to server

3. **Test Environment**
   - Network monitoring tools (Wireshark, netsh trace)
   - Ability to verify traffic routing
   - Ability to verify packet encryption

### Test Cases

1. **Connection Establishment**
   - Verify handshake completes
   - Verify adapter is created
   - Verify routes are added

2. **Packet Flow**
   - Send traffic through tunnel
   - Verify packets are encrypted
   - Verify packets reach server
   - Verify response packets are decrypted

3. **Disconnection**
   - Disconnect gracefully
   - Verify adapter is removed
   - Verify routes are removed
   - Verify traffic no longer flows through tunnel

4. **Reconnection**
   - Reconnect to same server
   - Verify adapter is reused
   - Verify traffic flows correctly

5. **Error Handling**
   - Test with invalid server endpoint
   - Test with unreachable server
   - Test with network interruption
   - Verify graceful error handling

### Testing Requirements

- Windows 10 or Windows 11
- WireGuard server (Linux or cloud)
- Network connectivity
- Wireshark or similar for packet inspection
- Administrator privileges

### Acceptance Criteria

- [PENDING] Connection handshake completes successfully
- [PENDING] Packets are encrypted and routed correctly
- [PENDING] Traffic flows through tunnel
- [PENDING] Disconnection cleans up properly
- [PENDING] Reconnection works correctly
- [PENDING] Error handling is graceful
- [PENDING] No packet loss or corruption

---

## Implementation Timeline

| Task | Estimated Time | Platform | Status |
|------|-----------------|----------|--------|
| 71 - macOS Handler | 4-6 hours | macOS 10.13+ | [PENDING] |
| 72 - Windows Validation | 6-8 hours | Windows 10/11 | [PENDING] |
| 73 - Bundle wintun.dll | 2-3 hours | Windows | [PENDING] |
| 74 - netsh Quoting | 2-3 hours | Windows | [PENDING] |
| 75 - Crash Cleanup | 4-6 hours | Windows | [PENDING] |
| 76 - E2E Smoke Test | 4-6 hours | Windows + Server | [PENDING] |

**Total Estimated Time**: 22-32 hours across macOS and Windows platforms

---

## Notes

- All tasks require actual platform access (macOS for 71, Windows for 72-76)
- Tasks should be completed in order (71 → 72-76)
- Each task has acceptance criteria that must be verified
- Comprehensive logging should be added for debugging
- Test results should be documented for future reference

---

## Next Steps

1. Obtain access to macOS and Windows test machines
2. Set up development environments on each platform
3. Implement and test each task in sequence
4. Document results and any platform-specific issues
5. Update MasterTODO as tasks are completed
