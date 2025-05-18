use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use socket2::{Socket, Domain, Type, Protocol};
use std::io;
use log::{info, warn, debug, error, trace};
use rand::Rng;
use tokio::sync::{Semaphore, mpsc};
use tokio::time;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use parking_lot::Mutex;
use std::mem::MaybeUninit;

/// Port state - simplified for scan results
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
}

/// Target structure representing an IP:port combination
#[derive(Debug, Clone, Copy)]
pub struct Target {
    pub addr: IpAddr,
    pub port: u16,
}

/// Results from port scanning
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub addr: IpAddr,
    pub port: u16,
    pub state: PortState,
    pub response_time_ms: u64,
}

/// Configuration for the scanner
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub targets: Vec<Target>,
    pub timeout_ms: u64,           // Response timeout in milliseconds
    pub max_concurrent_scans: usize, // Maximum number of concurrent scans
    pub batch_report_size: usize,  // How often to report progress
    pub retry_count: u8,           // Number of retries for ambiguous results
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            targets: Vec::new(),
            timeout_ms: 100,         // 100ms default timeout
            max_concurrent_scans: num_cpus::get() * 50, // Scale based on CPU cores
            batch_report_size: 100,  // Report every 100 ports
            retry_count: 1,          // One retry by default
        }
    }
}

// TCP and IP header structures remain the same as in the original code
// ...

/// Perform a highly concurrent SYN scan using raw sockets and Tokio
pub async fn scan_ports_concurrent(config: &ScanConfig) -> Vec<ScanResult> {
    debug!("Starting scan_ports_concurrent with config: {:?}", config);
    
    // Check if there are IPv6 targets - currently unsupported
    if config.targets.iter().any(|t| matches!(t.addr, IpAddr::V6(_))) {
        warn!("IPv6 targets detected but raw SYN scan only supports IPv4. IPv6 targets will be skipped.");
    }
    
    // Filter to only IPv4 targets
    let ipv4_targets: Vec<Target> = config.targets.iter()
        .filter(|t| matches!(t.addr, IpAddr::V4(_)))
        .cloned()
        .collect();
    
    debug!("Filtered to {} IPv4 targets from {} total targets", 
           ipv4_targets.len(), config.targets.len());
    
    if ipv4_targets.is_empty() {
        warn!("No valid IPv4 targets for SYN scan.");
        return Vec::new();
    }
    
    let total_targets = ipv4_targets.len();
    info!("Starting concurrent SYN scan of {} targets with up to {} concurrent scans", 
          total_targets, config.max_concurrent_scans);
    debug!("Timeout: {}ms, Retry count: {}", config.timeout_ms, config.retry_count);
    
    // Create shared resources
    let concurrent_limit = Arc::new(Semaphore::new(config.max_concurrent_scans));
    let (result_tx, mut result_rx) = mpsc::channel(config.max_concurrent_scans * 2);
    let results = Arc::new(Mutex::new(Vec::with_capacity(total_targets)));
    let progress = Arc::new(AtomicUsize::new(0));
    let open_count = Arc::new(AtomicUsize::new(0));
    let closed_count = Arc::new(AtomicUsize::new(0));
    let scan_start = Instant::now();
    
    debug!("Creating socket pool");
    
    // Create a socket pool for sending packets
    let socket_pool = create_socket_pool(num_cpus::get().min(16)).unwrap_or_else(|e| {
        error!("Failed to create socket pool: {}", e);
        Vec::new()
    });
    
    debug!("Created socket pool with {} sockets", socket_pool.len());
    
    if socket_pool.is_empty() {
        error!("Could not create any raw sockets. This usually means you don't have the required permissions.");
        error!("SYN scanning requires root/administrator privileges.");
        return Vec::new();
    }
    
    let socket_pool = Arc::new(socket_pool);
    
    debug!("Creating receiver sockets");
    
    // Create receiver sockets - one per worker thread
    let recv_sockets = create_receiver_sockets(num_cpus::get().min(8)).unwrap_or_else(|e| {
        error!("Failed to create receiver sockets: {}", e);
        Vec::new()
    });
    
    debug!("Created {} receiver sockets", recv_sockets.len());
    
    if recv_sockets.is_empty() {
        error!("Could not create any receiver sockets.");
        return Vec::new();
    }
    
    let recv_sockets = Arc::new(recv_sockets);
    
    debug!("Spawning scan tasks for {} targets", total_targets);
    let task_spawn_start = Instant::now();
    
    // Spawn tasks for each target
    for target in ipv4_targets {
        let permit = match concurrent_limit.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => {
                warn!("Failed to acquire concurrency permit - shutting down?");
                break;
            }
        };
        
        trace!("Acquired permit for target {}:{}", target.addr, target.port);
        
        let result_tx = result_tx.clone();
        let socket_pool = socket_pool.clone();
        let recv_sockets = recv_sockets.clone();
        let timeout = config.timeout_ms;
        let retry_count = config.retry_count;
        
        // Spawn task for this target
        tokio::spawn(async move {
            let scan_result = scan_single_target(
                &socket_pool, 
                &recv_sockets,
                target, 
                timeout, 
                retry_count
            ).await;
            
            // Send the result back to the collector
            if result_tx.send(scan_result).await.is_err() {
                warn!("Failed to send scan result - receiver dropped?");
            }
            
            // Return the permit when done
            trace!("Releasing permit for target {}:{}", target.addr, target.port);
            drop(permit);
        });
    }
    
    debug!("Spawned all scan tasks in {:.2?}", task_spawn_start.elapsed());
    
    // Drop the original sender so the channel can close when all tasks are done
    drop(result_tx);
    
    debug!("Starting collector task");
    
    // Collector task for progress reporting
    let progress_reporter = {
        let results = results.clone();
        let progress = progress.clone();
        let open_count = open_count.clone();
        let closed_count = closed_count.clone();
        let batch_size = config.batch_report_size;
        
        tokio::spawn(async move {
            let mut last_report_time = Instant::now();
            let mut last_count = 0;
            
            while let Some(result) = result_rx.recv().await {
                // Store the result
                {
                    let mut results_guard = results.lock();
                    results_guard.push(result.clone());
                }
                
                // Update counters
                let count = progress.fetch_add(1, Ordering::SeqCst) + 1;
                if result.state == PortState::Open {
                    let open = open_count.fetch_add(1, Ordering::SeqCst) + 1;
                    info!("OPEN PORT: {}:{} (responded in {}ms) [Finding #{} of scan]", 
                         result.addr, result.port, result.response_time_ms, open);
                } else {
                    closed_count.fetch_add(1, Ordering::SeqCst);
                }
                
                // Calculate real-time scan rate
                let time_since_last = last_report_time.elapsed();
                if time_since_last.as_secs() >= 2 {
                    let scans_since_last = count - last_count;
                    let rate_since_last = scans_since_last as f64 / time_since_last.as_secs_f64();
                    debug!("Current scan rate: {:.1} ports/sec (processed {} ports in last {:.1}s)",
                          rate_since_last, scans_since_last, time_since_last.as_secs_f64());
                    last_report_time = Instant::now();
                    last_count = count;
                }
                
                // Periodic progress reporting
                if count % batch_size == 0 || count == total_targets {
                    let progress_pct = (count as f64 / total_targets as f64) * 100.0;
                    let elapsed = scan_start.elapsed();
                    let ports_per_second = count as f64 / elapsed.as_secs_f64();
                    let open = open_count.load(Ordering::SeqCst);
                    let closed = closed_count.load(Ordering::SeqCst);
                    
                    let eta_seconds = if ports_per_second > 0.0 {
                        ((total_targets - count) as f64 / ports_per_second) as u64
                    } else {
                        0
                    };
                    
                    info!("Progress: {:.1}% ({}/{}) - {:.1} ports/sec - {} open, {} closed - ETA: {:.1}s", 
                         progress_pct, count, total_targets, ports_per_second, 
                         open, closed, eta_seconds as f64);
                         
                    // More detailed stats in debug mode
                    debug!("Memory stats: results size={}, time elapsed={:.2?}",
                          results.lock().len(), elapsed);
                }
            }
            
            debug!("Collector task completed - all results received");
        })
    };
    
    // Heartbeat to detect if scanning gets stuck
    let heartbeat = {
        let total_targets = total_targets;
        let progress = progress.clone();
        
        tokio::spawn(async move {
            let mut last_count = 0;
            let mut stuck_count = 0;
            
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                let current = progress.load(Ordering::SeqCst);
                
                info!("HEARTBEAT: Processed {}/{} ports ({}%)", 
                     current, total_targets, 
                     (current as f64 / total_targets as f64 * 100.0) as u32);
                
                // Check if we're making progress
                if current == last_count && current < total_targets {
                    stuck_count += 1;
                    warn!("Scan appears to be stuck! No progress for {} seconds. Try reducing concurrency.", 
                         stuck_count * 10);
                    
                    if stuck_count >= 3 {
                        error!("Scan stuck for 30 seconds. Consider restarting with lower concurrency.");
                    }
                } else {
                    stuck_count = 0;
                }
                
                last_count = current;
                
                // Exit when we've processed all targets
                if current >= total_targets {
                    debug!("Heartbeat: All targets processed, exiting heartbeat");
                    break;
                }
            }
        })
    };
    
    debug!("Waiting for collector task to complete");
    
    // Wait for collector to finish
    if let Err(e) = progress_reporter.await {
        error!("Progress reporter task failed: {}", e);
    }
    
    // Cancel heartbeat if it's still running
    heartbeat.abort();
    
    // Final report
    let total_time = scan_start.elapsed();
    let scan_rate = total_targets as f64 / total_time.as_secs_f64();
    let open = open_count.load(Ordering::SeqCst);
    let closed = closed_count.load(Ordering::SeqCst);
    
    info!("Concurrent SYN scan completed: {} targets in {:.2?} ({:.2} ports/second)",
         total_targets, total_time, scan_rate);
    info!("Found {} open ports, {} closed ports", open, closed);
    
    // Extra performance statistics in debug mode
    debug!("Performance stats:");
    debug!("  Average processing time: {:.3}ms per port", 
          (total_time.as_millis() as f64) / (total_targets as f64));
    debug!("  Concurrency limit: {}", config.max_concurrent_scans);
    debug!("  Socket pool size: {}", socket_pool.len());
    debug!("  Receiver sockets: {}", recv_sockets.len());
    
    // Return the results
    let final_results = {
        let guard = results.lock();
        guard.clone()
    };
    
    debug!("Returning {} scan results", final_results.len());
    final_results
}

/// Create a pool of sender sockets
fn create_socket_pool(count: usize) -> Result<Vec<Socket>, io::Error> {
    debug!("Creating socket pool with {} sockets", count);
    let mut sockets = Vec::with_capacity(count);
    let mut success = 0;
    let mut failures = 0;
    
    for i in 0..count {
        match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)) {
            Ok(socket) => {
                // Configure the socket if needed
                sockets.push(socket);
                success += 1;
                trace!("Created socket #{} for pool", i);
            },
            Err(e) => {
                failures += 1;
                warn!("Failed to create socket #{} for pool: {}", i, e);
                // Continue and try to create others
            }
        }
    }
    
    debug!("Socket pool creation complete: {} successful, {} failed", success, failures);
    
    if sockets.is_empty() {
        error!("Could not create any raw sockets - insufficient permissions?");
        Err(io::Error::new(io::ErrorKind::PermissionDenied, 
                          "Could not create any raw sockets - insufficient permissions?"))
    } else {
        Ok(sockets)
    }
}

/// Create receiver sockets
fn create_receiver_sockets(count: usize) -> Result<Vec<Socket>, io::Error> {
    debug!("Creating {} receiver sockets", count);
    let mut sockets = Vec::with_capacity(count);
    let mut success = 0;
    let mut failures = 0;
    
    for i in 0..count {
        match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)) {
            Ok(socket) => {
                // Set non-blocking mode
                if let Err(e) = socket.set_nonblocking(true) {
                    warn!("Failed to set non-blocking mode for socket #{}: {}", i, e);
                    failures += 1;
                    continue;
                }
                
                // Bind to all interfaces
                let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
                if let Err(e) = socket.bind(&bind_addr.into()) {
                    warn!("Failed to bind socket #{}: {}", i, e);
                    failures += 1;
                    continue;
                }
                
                trace!("Created and configured receiver socket #{}", i);
                sockets.push(socket);
                success += 1;
            },
            Err(e) => {
                warn!("Failed to create receiver socket #{}: {}", i, e);
                failures += 1;
                // Continue and try to create others
            }
        }
    }
    
    debug!("Receiver socket creation complete: {} successful, {} failed", success, failures);
    
    if sockets.is_empty() {
        error!("Could not create any receiver sockets - insufficient permissions?");
        Err(io::Error::new(io::ErrorKind::PermissionDenied, 
                          "Could not create any receiver sockets - insufficient permissions?"))
    } else {
        Ok(sockets)
    }
}

/// Scan a single target asynchronously
async fn scan_single_target(
    socket_pool: &[Socket],
    recv_sockets: &[Socket],
    target: Target,
    timeout_ms: u64,
    retry_count: u8
) -> ScanResult {
    trace!("scan_single_target starting for {}:{}", target.addr, target.port);
    
    // Create a hard timeout for the entire scan function
    let scan_result = tokio::time::timeout(
        tokio::time::Duration::from_millis(timeout_ms * (retry_count as u64 + 2) + 500),
        async {
            // Extract IPv4 address
            let ipv4_addr = match target.addr {
                IpAddr::V4(addr) => addr,
                _ => {
                    // This shouldn't happen as we filter IPv6 earlier
                    warn!("Received IPv6 address in scan_single_target: {}", target.addr);
                    return ScanResult {
                        addr: target.addr,
                        port: target.port,
                        state: PortState::Closed,
                        response_time_ms: 0,
                    };
                }
            };
            
            // Generate a random source port
            let source_port = rand::thread_rng().gen_range(49152..65535);
            let target_start = Instant::now();
            
            // Pick a socket from the pool using a simple hash
            let socket_index = (target.port as usize) % socket_pool.len();
            let send_socket = &socket_pool[socket_index];
            
            // Pick a receiver socket
            let recv_index = (target.port as usize) % recv_sockets.len();
            let recv_socket = &recv_sockets[recv_index];
            
            trace!("Using send_socket[{}] and recv_socket[{}] for target {}:{}",
                socket_index, recv_index, ipv4_addr, target.port);
            
            // Default to closed
            let mut state = PortState::Closed;
            
            // Retry loop
            for retry in 0..=retry_count {
                if retry > 0 {
                    debug!("Retry #{} for {}:{}", retry, ipv4_addr, target.port);
                }
                
                // Create and send the SYN packet
                if let Err(e) = send_syn_packet(send_socket, source_port, ipv4_addr, target.port) {
                    warn!("Failed to send SYN packet to {}:{}: {}", ipv4_addr, target.port, e);
                    continue;
                }
                
                trace!("Sent SYN packet to {}:{} (from source port {})", 
                    ipv4_addr, target.port, source_port);
                
                // Async wait for response with timeout
                let timeout_duration = Duration::from_millis(timeout_ms);
                
                // Clone the socket to avoid borrowing issues
                let socket_clone = match recv_socket.try_clone() {
                    Ok(socket) => socket,
                    Err(e) => {
                        warn!("Failed to clone socket for {}:{}: {}", ipv4_addr, target.port, e);
                        continue;
                    }
                };
                
                trace!("Starting receive task for {}:{} with timeout {}ms", 
                    ipv4_addr, target.port, timeout_ms);
                
                let response_result = tokio::task::spawn_blocking(move || {
                    // This uses a separate thread since raw socket recv() can't be made async easily
                    let mut local_buffer = [MaybeUninit::<u8>::uninit(); 2048];
                    receive_syn_response(&socket_clone, source_port, ipv4_addr, target.port,
                                    timeout_ms, &mut local_buffer)
                });
                
                match time::timeout(timeout_duration, response_result).await {
                    Ok(Ok(Ok(true))) => {
                        // Port is open
                        state = PortState::Open;
                        trace!("Found OPEN port at {}:{}", ipv4_addr, target.port);
                        break;
                    },
                    Ok(Ok(Ok(false))) => {
                        // Port is closed
                        state = PortState::Closed;
                        trace!("Found CLOSED port at {}:{}", ipv4_addr, target.port);
                        break;
                    },
                    Ok(Ok(Err(e))) => {
                        trace!("Error receiving response from {}:{}: {}", ipv4_addr, target.port, e);
                        // Error during receive, try again if retries left
                        if retry >= retry_count {
                            debug!("Max retries reached for {}:{}, marking as closed", ipv4_addr, target.port);
                            break;
                        }
                    },
                    Ok(Err(e)) => {
                        debug!("Receive task failed for {}:{}: {}", ipv4_addr, target.port, e);
                        // Task join error, try again if retries left
                        if retry >= retry_count {
                            break;
                        }
                    },
                    Err(_) => {
                        trace!("Timeout waiting for response from {}:{}", ipv4_addr, target.port);
                        // Timeout, try again if retries left
                        if retry >= retry_count {
                            debug!("Max retries reached for {}:{}, marking as closed", ipv4_addr, target.port);
                            break;
                        }
                    }
                }
            }
            
            // Calculate response time
            let elapsed_ms = target_start.elapsed().as_millis() as u64;
            
            trace!("scan_single_target completed for {}:{} in {}ms - state:{:?}", 
                ipv4_addr, target.port, elapsed_ms, state);
            
            ScanResult {
                addr: target.addr,
                port: target.port,
                state,
                response_time_ms: elapsed_ms,
            }
        }
    ).await;
    
    // Return result or a timeout result if the entire scan function timed out
    match scan_result {
        Ok(result) => result,
        Err(_) => {
            warn!("Hard timeout in scan_single_target for {}:{}", target.addr, target.port);
            ScanResult {
                addr: target.addr,
                port: target.port,
                state: PortState::Closed,
                response_time_ms: timeout_ms * (retry_count as u64 + 1),
            }
        }
    }
}

/// TCP Header structure for raw packet construction
#[repr(C, packed)]
struct TcpHeader {
    source_port: u16,
    dest_port: u16,
    sequence: u32,
    acknowledgement: u32,
    offset_and_flags: u16,  // Data offset (4 bits), Reserved (3 bits), and Flags (9 bits)
    window: u16,
    checksum: u16,
    urgent_ptr: u16,
}

/// IPv4 Header structure for raw packet construction
#[repr(C, packed)]
struct Ipv4Header {
    version_and_ihl: u8,    // Version (4 bits) and Internet Header Length (4 bits)
    tos: u8,                // Type of Service
    total_length: u16,      // Total Length
    identification: u16,    // Identification
    flags_and_fragment: u16, // Flags (3 bits) and Fragment Offset (13 bits)
    ttl: u8,                // Time to Live
    protocol: u8,           // Protocol
    header_checksum: u16,   // Header Checksum
    source_ip: u32,         // Source Address
    dest_ip: u32,           // Destination Address
    // Options and padding are not included
}

/// Pseudo header for TCP checksum calculation
#[repr(C, packed)]
struct PseudoHeader {
    source_ip: u32,       // Source IP
    dest_ip: u32,         // Destination IP
    zero: u8,             // Reserved (0)
    protocol: u8,         // Protocol
    tcp_length: u16,      // TCP length
}

/// Constants for packet construction
const TCP_HEADER_SIZE: usize = std::mem::size_of::<TcpHeader>();
const IP_HEADER_SIZE: usize = std::mem::size_of::<Ipv4Header>();
const TCP_SYN_FLAG: u16 = 0x0002;
const TCP_ACK_FLAG: u16 = 0x0010;
const TCP_RST_FLAG: u16 = 0x0004;
const TCP_DATA_OFFSET: u16 = 5 << 12; // 5 32-bit words

/// Convert IPv4 address to u32
fn ipv4_to_u32(addr: Ipv4Addr) -> u32 {
    let octets = addr.octets();
    ((octets[0] as u32) << 24) | ((octets[1] as u32) << 16) | ((octets[2] as u32) << 8) | (octets[3] as u32)
}

/// Convert u32 to IPv4 address
fn u32_to_ipv4(addr: u32) -> Ipv4Addr {
    let octet1 = ((addr >> 24) & 0xFF) as u8;
    let octet2 = ((addr >> 16) & 0xFF) as u8;
    let octet3 = ((addr >> 8) & 0xFF) as u8;
    let octet4 = (addr & 0xFF) as u8;
    Ipv4Addr::new(octet1, octet2, octet3, octet4)
}

/// Calculate TCP/IP checksum
fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    
    // Add 16-bit words
    while i + 1 < data.len() {
        let word = (data[i] as u32) << 8 | (data[i + 1] as u32);
        sum += word;
        i += 2;
    }
    
    // Add any remaining byte
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // One's complement
    !(sum as u16)
}

/// Send a SYN packet using a raw socket
fn send_syn_packet(
    socket: &Socket,
    source_port: u16,
    dest_ip: Ipv4Addr,
    dest_port: u16
) -> Result<(), io::Error> {
    trace!("Sending SYN packet to {}:{} from source port {}", dest_ip, dest_port, source_port);
    
    // Get the local IP
    let local_ip = match get_default_source_ip() {
        Ok(ip) => {
            trace!("Using source IP: {}", ip);
            ip
        },
        Err(e) => {
            warn!("Failed to get default source IP: {}, fallback to localhost", e);
            Ipv4Addr::new(127, 0, 0, 1)
        }
    };
    
    // Create a packet buffer
    let mut packet = [0u8; IP_HEADER_SIZE + TCP_HEADER_SIZE];
    
    // Prepare the IP header
    let ip_header = unsafe { &mut *(packet.as_mut_ptr() as *mut Ipv4Header) };
    
    // Set IP header fields
    ip_header.version_and_ihl = 0x45;  // IPv4, 5 32-bit words
    ip_header.tos = 0;
    ip_header.total_length = u16::to_be((IP_HEADER_SIZE + TCP_HEADER_SIZE) as u16);
    ip_header.identification = rand::random::<u16>().to_be();
    ip_header.flags_and_fragment = 0x4000u16.to_be();  // Don't fragment
    ip_header.ttl = 64;
    ip_header.protocol = 6;  // TCP
    ip_header.header_checksum = 0;
    ip_header.source_ip = ipv4_to_u32(local_ip).to_be();
    ip_header.dest_ip = ipv4_to_u32(dest_ip).to_be();
    
    // Calculate IP header checksum
    ip_header.header_checksum = calculate_checksum(&packet[0..IP_HEADER_SIZE]).to_be();
    
    // Prepare the TCP header
    let tcp_header = unsafe { &mut *(packet[IP_HEADER_SIZE..].as_mut_ptr() as *mut TcpHeader) };
    
    // Set TCP header fields
    tcp_header.source_port = source_port.to_be();
    tcp_header.dest_port = dest_port.to_be();
    tcp_header.sequence = rand::random::<u32>().to_be();
    tcp_header.acknowledgement = 0;
    tcp_header.offset_and_flags = (TCP_DATA_OFFSET | TCP_SYN_FLAG).to_be();
    tcp_header.window = 64240u16.to_be();
    tcp_header.checksum = 0;
    tcp_header.urgent_ptr = 0;
    
    // Calculate TCP checksum with pseudo-header
    let pseudo_header = PseudoHeader {
        source_ip: ipv4_to_u32(local_ip).to_be(),
        dest_ip: ipv4_to_u32(dest_ip).to_be(),
        zero: 0,
        protocol: 6,  // TCP
        tcp_length: TCP_HEADER_SIZE as u16,
    };
    
    // Prepare checksum buffer
    let mut checksum_buffer = [0u8; std::mem::size_of::<PseudoHeader>() + TCP_HEADER_SIZE];
    
    // Copy pseudo-header to checksum buffer
    unsafe {
        std::ptr::copy_nonoverlapping(
            &pseudo_header as *const _ as *const u8,
            checksum_buffer.as_mut_ptr(),
            std::mem::size_of::<PseudoHeader>()
        );
        
        // Copy TCP header to checksum buffer after pseudo-header
        std::ptr::copy_nonoverlapping(
            tcp_header as *const _ as *const u8,
            checksum_buffer.as_mut_ptr().add(std::mem::size_of::<PseudoHeader>()),
            TCP_HEADER_SIZE
        );
    }
    
    // Calculate and set TCP checksum
    tcp_header.checksum = calculate_checksum(&checksum_buffer).to_be();
    
    // Send the packet
    let dest_addr = SocketAddr::new(IpAddr::V4(dest_ip), dest_port);
    match socket.send_to(&packet, &dest_addr.into()) {
        Ok(bytes) => {
            trace!("Sent {} bytes to {}:{}", bytes, dest_ip, dest_port);
            Ok(())
        },
        Err(e) => {
            debug!("Failed to send packet to {}:{}: {}", dest_ip, dest_port, e);
            Err(e)
        }
    }
}

/// Get the default source IP address
fn get_default_source_ip() -> Result<Ipv4Addr, io::Error> {
    // For simplicity, use a fixed IP
    // In a real application, determine the actual interface IP
    Ok(Ipv4Addr::new(127, 0, 0, 1))
}

/// Receive and analyze response to SYN packet
/// 
/// Returns:
/// - Ok(true) if port is open (SYN-ACK received)
/// - Ok(false) if port is closed (RST received)
/// - Err(_) if timeout or error
fn receive_syn_response(
    socket: &Socket,
    source_port: u16,
    dest_ip: Ipv4Addr,
    dest_port: u16,
    timeout_ms: u64,
    buffer: &mut [MaybeUninit<u8>]
) -> Result<bool, io::Error> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    
    let mut packets_checked = 0;
    
    while Instant::now() < deadline {
        // Try to receive a packet
        match socket.recv(buffer) {
            Ok(size) if size >= IP_HEADER_SIZE + TCP_HEADER_SIZE => {
                packets_checked += 1;
                
                // Convert received data to normal buffer
                let received_data = unsafe {
                    std::slice::from_raw_parts(buffer.as_ptr() as *const u8, size)
                };
                
                // Process the packet
                let ip_header = unsafe { &*(received_data.as_ptr() as *const Ipv4Header) };
                
                // Convert network byte order to host byte order
                let src_ip = u32_to_ipv4(u32::from_be(ip_header.source_ip));
                let proto = ip_header.protocol;
                
                // Check if it's a TCP packet from our target
                if proto == 6 && src_ip == dest_ip {
                    // Get TCP header
                    let tcp_offset = (ip_header.version_and_ihl & 0x0F) as usize * 4;
                    if size < tcp_offset + TCP_HEADER_SIZE {
                        trace!("Received TCP packet too small from {}:{}, continuing", src_ip, dest_port);
                        continue;
                    }
                    
                    let tcp_header = unsafe { &*(received_data[tcp_offset..].as_ptr() as *const TcpHeader) };
                    
                    // Convert network byte order to host byte order
                    let src_port = u16::from_be(tcp_header.source_port);
                    let dst_port = u16::from_be(tcp_header.dest_port);
                    let flags = u16::from_be(tcp_header.offset_and_flags) & 0x3F;
                    
                    trace!("Checking TCP packet: {}:{} -> {}:{} (flags: {:02x})", 
                         src_ip, src_port, "local", dst_port, flags);
                    
                    // Check if it's a response to our packet
                    if src_port == dest_port && dst_port == source_port {
                        trace!("Received relevant response from {}:{} to source port {}", 
                             src_ip, src_port, dst_port);
                        
                        // Check flags to determine port state
                        
                        // SYN-ACK means port is open
                        if (flags & (TCP_SYN_FLAG | TCP_ACK_FLAG)) == (TCP_SYN_FLAG | TCP_ACK_FLAG) {
                            trace!("Port {}:{} is OPEN (SYN-ACK) after checking {} packets", 
                                 dest_ip, dest_port, packets_checked);
                            return Ok(true);
                        }
                        
                        // RST means port is closed
                        if (flags & TCP_RST_FLAG) != 0 {
                            trace!("Port {}:{} is CLOSED (RST) after checking {} packets", 
                                 dest_ip, dest_port, packets_checked);
                            return Ok(false);
                        }
                        
                        trace!("Received unexpected flags: {:02x} from {}:{}, continuing", 
                             flags, src_ip, src_port);
                    }
                }
            },
            Ok(size) => {
                trace!("Received packet too small ({} bytes) to be a valid TCP response", size);
            },
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No data available, wait a bit (but less than before)
                std::thread::sleep(Duration::from_micros(100));
            },
            Err(e) => {
                // Real error
                debug!("Error receiving packet: {}", e);
                return Err(e);
            }
        }
    }
    
    // Timeout reached
    trace!("Timeout reached waiting for response from {}:{} after checking {} packets", 
         dest_ip, dest_port, packets_checked);
    Err(io::Error::new(io::ErrorKind::TimedOut, "Timeout waiting for response"))
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
    
    info!("Summary created: found {} hosts with open ports", summary.len());
    for (addr, ports) in &summary {
        info!("Host {} has {} open ports", addr, ports.len());
        debug!("Open ports on {}: {:?}", addr, ports);
    }
    
    summary
}

/// Simple helper function to create common port ranges
pub fn create_port_range(addr: IpAddr, start_port: u16, end_port: u16) -> Vec<Target> {
    let mut targets = Vec::with_capacity((end_port - start_port + 1) as usize);
    
    for port in start_port..=end_port {
        targets.push(Target { addr, port });
    }
    
    targets
}

/// Example usage function
pub async fn scan_example() {
    use std::str::FromStr;
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();
    
    // Configure scan
    let target_ip = IpAddr::from_str("127.0.0.1").unwrap();
    let targets = create_port_range(target_ip, 4900, 5200); // Scan first 10000 ports
    
    let config = ScanConfig {
        targets,
        timeout_ms: 150,             // 100ms timeout
        max_concurrent_scans: num_cpus::get() * 2, // Scale based on CPU cores
        batch_report_size: 1000,     // Report progress every 1000 ports
        retry_count: 2,              // No retries for maximum speed
    };
    
    // Run the scan
    let results = scan_ports_concurrent(&config).await;
    
    // Summarize results
    let summary = summarize_open_ports(&results);
    
    // Print summary
    println!("\n--- SCAN SUMMARY ---");
    for (ip, ports) in &summary {
        println!("{}: {} open ports {:?}", ip, ports.len(), ports);
    }
}

// Main function to run the example
#[tokio::main]
async fn main() {
    scan_example().await;
}