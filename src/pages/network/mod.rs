pub mod scanner;
pub mod types;

// Re-export key items for easier access
pub use scanner::{scan_ports, scan_ports_tcp_connect};
pub use types::{ScanConfig, ScanResult, PortState, Target};

use std::time::Duration;
use std::net::IpAddr;

/// Quickly scan a range of ports on a target IP
/// 
/// This is a convenient wrapper around the raw scan_ports function.
/// It will attempt to use SYN scanning first (requires root/admin privileges),
/// and fall back to TCP connect scanning if necessary.
/// 
/// # Arguments
/// 
/// * `target_ip` - The IP address to scan
/// * `port_start` - The starting port number
/// * `port_end` - The ending port number (inclusive)
/// * `timeout_ms` - Timeout for each port in milliseconds
/// * `batch_size` - How many ports to scan simultaneously
/// 
/// # Returns
/// 
/// A vector of ScanResult containing open ports
/// 
/// # Example
/// 
/// ```
/// use std::net::IpAddr;
/// use std::str::FromStr;
/// 
/// let target = IpAddr::from_str("1.1.1.1").unwrap();
/// let results = scan_ports_range(target, 80, 443, 1000, 100).await;
/// for result in results {
///     if let PortState::Open = result.state {
///         println!("Port {} is open", result.port);
///     }
/// }
/// ```
pub async fn scan_ports_range(
    target_ip: IpAddr,
    port_start: u16,
    port_end: u16,
    timeout_ms: u64,
    batch_size: usize,
) -> Vec<ScanResult> {
    let mut targets = Vec::with_capacity((port_end - port_start + 1) as usize);
    
    for port in port_start..=port_end {
        targets.push(Target {
            addr: target_ip,
            port,
        });
    }
    
    let config = ScanConfig {
        targets,
        timeout: Duration::from_millis(timeout_ms),
        batch_size,
        rate_limit: None,
        retry_count: 1,
    };
    
    // Try SYN scan first, fall back to TCP connect
    let results = scan_ports(&config).await;
    if results.is_empty() {
        // SYN scan probably failed due to permissions, use TCP connect
        scan_ports_tcp_connect(&config).await
    } else {
        results
    }
}

/// Quickly scan a specific set of ports on a target IP
pub async fn scan_specific_ports(
    target_ip: IpAddr,
    ports: &[u16],
    timeout_ms: u64,
    batch_size: usize,
) -> Vec<ScanResult> {
    let mut targets = Vec::with_capacity(ports.len());
    
    for &port in ports {
        targets.push(Target {
            addr: target_ip,
            port,
        });
    }
    
    let config = ScanConfig {
        targets,
        timeout: Duration::from_millis(timeout_ms),
        batch_size,
        rate_limit: None,
        retry_count: 1,
    };
    
    // Try SYN scan first, fall back to TCP connect
    let results = scan_ports(&config).await;
    if results.is_empty() {
        // SYN scan probably failed due to permissions, use TCP connect
        scan_ports_tcp_connect(&config).await
    } else {
        results
    }
}
