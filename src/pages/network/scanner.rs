use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};
use std::io::Error as IoError;
use std::thread;
use std::collections::HashMap;
use log::{info, warn, debug, error, trace};

// Simple port state enum - just Open or Closed for high-speed scanning
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
}

// Target structure (similar to your existing code)
#[derive(Debug, Clone, Copy)]
pub struct Target {
    pub addr: IpAddr,
    pub port: u16,
}

// Results from port scanning
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub addr: IpAddr,
    pub port: u16,
    pub state: PortState,
    pub response_time_ms: u64,
}

// Configuration for the scanner
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub targets: Vec<Target>,
    pub timeout_ms: u64,           // Connection timeout in milliseconds
    pub pause_between_ms: u64,     // Optional pause between scans (to avoid overwhelming)
    pub batch_report_size: usize,  // How often to report progress
}

impl Default for ScanConfig {
    fn default() -> Self {
        let config = ScanConfig {
            targets: Vec::new(),
            timeout_ms: 200,        // Default 200ms timeout
            pause_between_ms: 0,    // No pause by default
            batch_report_size: 100, // Report every 100 ports
        };
        debug!("Created default ScanConfig: timeout={}ms, pause={}ms, batch_size={}", 
            config.timeout_ms, config.pause_between_ms, config.batch_report_size);
        config
    }
}

/// High-speed sequential port scanner
/// This implementation uses standard library's TcpStream with connection timeout
/// Instead of relying on async runtime, it focuses on quick connect attempts
pub fn scan_ports_sequential(config: &ScanConfig) -> Vec<ScanResult> {
    let scan_start = Instant::now();
    let total_targets = config.targets.len();
    let mut results = Vec::with_capacity(total_targets);
    let mut open_count = 0;
    let mut closed_count = 0;
    
    info!("Starting high-speed sequential scan of {} targets", total_targets);
    info!("Scan configuration: timeout={}ms, pause={}ms, batch_report_size={}", 
          config.timeout_ms, config.pause_between_ms, config.batch_report_size);
    
    if config.targets.is_empty() {
        warn!("Empty target list provided to scanner, finishing immediately");
        return results;
    }
    
    // Log a sample of targets for debugging
    if total_targets > 5 {
        debug!("First 5 targets: {:?}", &config.targets[0..5]);
    } else {
        debug!("All targets: {:?}", &config.targets);
    }
    
    // Scan each target sequentially
    for (index, target) in config.targets.iter().enumerate() {
        let socket_addr = SocketAddr::new(target.addr, target.port);
        trace!("[{}/{}] Attempting connection to {}:{}", 
              index + 1, total_targets, target.addr, target.port);
        
        let target_start = Instant::now();
        
        // Attempt connection with timeout
        let result = TcpStream::connect_timeout(&socket_addr, Duration::from_millis(config.timeout_ms));
        
        // Process result
        let elapsed_ms = target_start.elapsed().as_millis() as u64;
        let state = match result {
            Ok(stream) => {
                open_count += 1;
                debug!("Successfully connected to {}:{} ({}ms)", target.addr, target.port, elapsed_ms);
                // Attempt to get more information about the connection
                match stream.peer_addr() {
                    Ok(peer) => trace!("Peer address details: {:?}", peer),
                    Err(e) => trace!("Unable to get peer details: {}", e),
                }
                PortState::Open
            },
            Err(err) => {
                closed_count += 1;
                match err.kind() {
                    std::io::ErrorKind::TimedOut => {
                        trace!("Connection to {}:{} timed out after {}ms", target.addr, target.port, elapsed_ms);
                    },
                    std::io::ErrorKind::ConnectionRefused => {
                        trace!("Connection to {}:{} was explicitly refused", target.addr, target.port);
                    },
                    _ => {
                        trace!("Connection to {}:{} failed: {} ({}ms)", 
                              target.addr, target.port, err, elapsed_ms);
                    }
                }
                PortState::Closed
            }
        };
        
        // Store result
        results.push(ScanResult {
            addr: target.addr,
            port: target.port,
            state,
            response_time_ms: elapsed_ms,
        });
        
        // Log open ports immediately
        if state == PortState::Open {
            info!("OPEN PORT: {}:{} (responded in {}ms)", target.addr, target.port, elapsed_ms);
        }
        
        // Periodic progress updates
        if (index + 1) % config.batch_report_size == 0 || index + 1 == total_targets {
            let progress_pct = ((index + 1) as f64 / total_targets as f64) * 100.0;
            let elapsed = scan_start.elapsed();
            let ports_per_second = (index + 1) as f64 / elapsed.as_secs_f64();
            let estimated_remaining_secs = if ports_per_second > 0.0 {
                (total_targets - (index + 1)) as f64 / ports_per_second
            } else {
                0.0
            };
            
            info!("Progress: {:.1}% ({}/{}) - {:.1} ports/sec - {} open, {} closed - ETA: {:.1}s", 
                progress_pct, index + 1, total_targets, ports_per_second, 
                open_count, closed_count, estimated_remaining_secs);
                
            // Log memory stats if we have a large scan
            if total_targets > 10000 {
                debug!("Memory usage: results vector capacity = {} items", results.capacity());
            }
        }
        
        // Optional pause between connections
        if config.pause_between_ms > 0 {
            trace!("Pausing for {}ms before next connection", config.pause_between_ms);
            thread::sleep(Duration::from_millis(config.pause_between_ms));
        }
    }
    
    // Final report
    let total_time = scan_start.elapsed();
    let scan_rate = total_targets as f64 / total_time.as_secs_f64();
    
    info!("Scan completed: {} targets in {:.2?} ({:.2} ports/second)",
         total_targets, total_time, scan_rate);
    info!("Found {} open ports, {} closed ports", open_count, closed_count);
    
    // Log distribution of response times
    let mut response_times = results.iter()
        .map(|r| r.response_time_ms)
        .collect::<Vec<_>>();
    response_times.sort_unstable();
    
    if !response_times.is_empty() {
        let min = response_times[0];
        let max = response_times[response_times.len() - 1];
        let median = response_times[response_times.len() / 2];
        let avg = response_times.iter().sum::<u64>() as f64 / response_times.len() as f64;
        
        debug!("Response time stats: min={}ms, max={}ms, median={}ms, avg={:.2}ms",
              min, max, median, avg);
    }
    
    results
}

/// Create a summary of open ports by IP address
pub fn summarize_open_ports(results: &[ScanResult]) -> HashMap<IpAddr, Vec<u16>> {
    debug!("Creating summary from {} scan results", results.len());
    let mut summary = HashMap::new();
    
    for result in results {
        if result.state == PortState::Open {
            summary.entry(result.addr)
                .or_insert_with(Vec::new)
                .push(result.port);
        }
    }
    
    // Sort port lists for better readability
    for ports in summary.values_mut() {
        ports.sort_unstable();
    }
    
    info!("Summary created: {} hosts with open ports", summary.len());
    for (addr, ports) in &summary {
        debug!("Host {} has {} open ports", addr, ports.len());
        trace!("Open ports on {}: {:?}", addr, ports);
    }
    
    summary
}

/// Simple helper function to create common port ranges
pub fn create_port_range(addr: IpAddr, start_port: u16, end_port: u16) -> Vec<Target> {
    debug!("Creating port range for {} from {} to {} ({} ports)", 
          addr, start_port, end_port, end_port - start_port + 1);
    
    if start_port > end_port {
        warn!("Invalid port range: start_port ({}) > end_port ({})", start_port, end_port);
        return Vec::new();
    }
    
    let mut targets = Vec::with_capacity((end_port - start_port + 1) as usize);
    
    for port in start_port..=end_port {
        targets.push(Target { addr, port });
    }
    
    trace!("Created {} targets for address {}", targets.len(), addr);
    targets
}

/// Example usage function
pub fn scan_example() {
    use std::str::FromStr;
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();
    
    info!("Starting scanner example");
    
    // Configure scan
    let target_ip = match IpAddr::from_str("127.0.0.1") {
        Ok(ip) => ip,
        Err(e) => {
            error!("Failed to parse IP address: {}", e);
            return;
        }
    };
    
    debug!("Creating port range for localhost scan");
    let targets = create_port_range(target_ip, 1, 10000); // Scan first 1000 ports
    
    let config = ScanConfig {
        targets,
        timeout_ms: 150,             // Very fast 150ms timeout
        pause_between_ms: 0,         // No pause between attempts
        batch_report_size: 100,      // Report progress every 100 ports
    };
    
    info!("Starting example scan of localhost ports 1-1000");
    
    // Run the scan
    let scan_start = Instant::now();
    let results = scan_ports_sequential(&config);
    let scan_duration = scan_start.elapsed();
    
    info!("Completed localhost scan in {:.2?}", scan_duration);
    
    // Summarize results
    debug!("Creating results summary");
    let summary = summarize_open_ports(&results);
    
    // Print summary
    println!("\n--- SCAN SUMMARY ---");
    if summary.is_empty() {
        println!("No open ports found.");
        info!("No open ports found in scan");
    } else {
        for (ip, ports) in &summary {
            println!("{}: {} open ports {:?}", ip, ports.len(), ports);
            info!("Host {} has {} open ports: {:?}", ip, ports.len(), ports);
        }
    }
    
    info!("Example scan completed successfully");
}

// This utility scans faster but will miss some open ports if:
// 1. The target has high latency (increase timeout_ms)
// 2. The network is congested (add pause_between_ms)
// 3. The port responds slowly (increase timeout_ms)

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    
    #[test]
    fn test_localhost_scan() {
        info!("Starting localhost unit test");
        
        // This test assumes that port 80 might be open on localhost
        let localhost = IpAddr::from_str("127.0.0.1").unwrap();
        let targets = vec![
            Target { addr: localhost, port: 80 },
            Target { addr: localhost, port: 81 }, // Likely closed
        ];
        
        let config = ScanConfig {
            targets,
            timeout_ms: 200,
            pause_between_ms: 0,
            batch_report_size: 1,
        };
        
        debug!("Running test scan with config: {:?}", config);
        let results = scan_ports_sequential(&config);
        assert_eq!(results.len(), 2);
        
        // Print results for debugging
        for result in &results {
            debug!("Test result - Port {}: {:?} ({}ms)", 
                   result.port, result.state, result.response_time_ms);
        }
        
        info!("Completed localhost unit test");
    }
}