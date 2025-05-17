use crate::pages::network::types::{PortState, ScanConfig, ScanResult, Target};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption};
use pnet::packet::Packet;
use pnet::transport::{self, TransportChannelType};
use pnet::util;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::time::{sleep, timeout};
use futures::stream::{self, StreamExt};
use rand::Rng;
use crossbeam_channel;
use std::os::unix::io::AsRawFd;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::mpsc;
use num_cpus;
use log::{info, warn, debug, error, trace};
use parking_lot::Mutex as PLMutex;

const TCP_HEADER_SIZE: usize = 20;
const DEFAULT_TTL: u8 = 64;
const SYN_PACKET_SIZE: usize = 20 + TCP_HEADER_SIZE; // IP header + TCP header

// Fast non-blocking SYN scanner
pub async fn scan_ports(config: &ScanConfig) -> Vec<ScanResult> {
    info!("Starting scan of {} targets with batch size {}", config.targets.len(), config.batch_size);
    
    // For collecting results across threads
    let results = Arc::new(Mutex::new(Vec::with_capacity(config.targets.len())));
    
    // Use a more efficient channel size
    let channel_size = config.targets.len().min(10000); // Avoid excessively large channels
    let (tx, rx) = crossbeam_channel::bounded::<Target>(channel_size);
    
    // Determine optimal worker count - more workers for large scans
    let worker_count = if config.targets.len() > 1000 {
        num_cpus::get().max(4)
    } else {
        num_cpus::get().min(config.batch_size).max(2)
    };
    
    info!("Using {} worker threads for scan", worker_count);
    
    // Pre-allocate worker handles
    let mut worker_handles = Vec::with_capacity(worker_count);
    
    // Track start time for rate calculations
    let scan_start = Instant::now();
    
    // Spawn worker tasks
    for worker_id in 0..worker_count {
        let rx: crossbeam_channel::Receiver<Target> = rx.clone();
        let results = Arc::clone(&results);
        let timeout_duration = config.timeout;
        let retry_count = config.retry_count;
        let rate_limit = config.rate_limit;
        
        let handle = tokio::spawn(async move {
            debug!("Worker {} starting", worker_id);
            // Preallocate a reasonably sized buffer for results to avoid frequent reallocations
            let mut local_results = Vec::with_capacity(1000);
            
            // Track consecutive failures for adaptive behavior
            let mut consecutive_failures: u32 = 0;
            
            // Create worker-local socket
            let worker_socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)) {
                Ok(socket) => {
                    if let Err(e) = socket.set_nonblocking(true) {
                        error!("Worker {}: Failed to set socket to non-blocking: {}", worker_id, e);
                        None
                    } else {
                        debug!("Worker {}: Created raw socket successfully", worker_id);
                        Some(socket)
                    }
                },
                Err(e) => {
                    error!("Worker {}: Failed to create raw socket: {}", worker_id, e);
                    None
                }
            };
            
            // If we couldn't create a socket, exit early
            if worker_socket.is_none() {
                warn!("Worker {} exiting due to socket creation failure", worker_id);
                return;
            }
            
            let worker_socket = worker_socket.unwrap();
            
            // Process targets from the channel
            let mut processed_count = 0;
            while let Ok(target) = rx.recv() {
                let start_time = Instant::now();
                
                trace!("Worker {}: Processing target {}:{}", worker_id, target.addr, target.port);
                
                // Process the target with the worker's socket
                let state = process_target(&worker_socket, target, timeout_duration, retry_count, &mut consecutive_failures).await;
                
                // Store result
                local_results.push(ScanResult {
                    addr: target.addr,
                    port: target.port,
                    state,
                });
                
                processed_count += 1;
                
                // Log open ports immediately
                if state == PortState::Open {
                    info!("Open port found: {}:{}", target.addr, target.port);
                }
                
                // Periodically flush results to shared collection
                if local_results.len() >= 1000 {
                    if let Ok(mut shared_results) = results.lock() {
                        shared_results.extend(local_results.drain(..));
                        debug!("Worker {}: Flushed results batch", worker_id);
                    }
                }
                
                // Log periodic progress
                if processed_count % 1000 == 0 {
                    debug!("Worker {}: Processed {} targets", worker_id, processed_count);
                }
                
                // Enforce rate limiting if configured
                if let Some(rate) = rate_limit {
                    let elapsed = start_time.elapsed();
                    let target_duration = Duration::from_secs_f64(1.0 / rate as f64);
                    if elapsed < target_duration {
                        let sleep_duration = target_duration - elapsed;
                        trace!("Worker {}: Rate limiting, sleeping for {:?}", worker_id, sleep_duration);
                        sleep(sleep_duration).await;
                    }
                }
            }
            
            // Final flush of local results
            if !local_results.is_empty() {
                if let Ok(mut shared_results) = results.lock() {
                    debug!("Worker {}: Final flush of {} results", worker_id, local_results.len());
                    shared_results.extend(local_results);
                }
            }
            
            info!("Worker {} completed, processed {} targets", worker_id, processed_count);
        });
        
        worker_handles.push(handle);
    }
    
    // Send targets to workers with a batch approach for large target sets
    if config.targets.len() > 10000 {
        // Batch sending for very large scans to avoid channel pressure
        info!("Using batched sending for large scan ({} targets)", config.targets.len());
        for (i, chunk) in config.targets.chunks(1000).enumerate() {
            for target in chunk {
                if let Err(e) = tx.send(*target) {
                    error!("Failed to send target to worker: {}", e);
                    break;
                }
            }
            // Small yield to allow workers to make progress
            tokio::task::yield_now().await;
            debug!("Sent batch {}, progress: {:.1}%", i+1, (i+1) * 1000 * 100 / config.targets.len());
        }
    } else {
        // Direct sending for smaller scans
        info!("Using direct sending for scan ({} targets)", config.targets.len());
        for target in &config.targets {
            if let Err(e) = tx.send(*target) {
                error!("Failed to send target to worker: {}", e);
                break;
            }
        }
    }
    
    // Drop original sender to signal completion
    drop(tx);
    info!("All targets sent to workers, waiting for completion");
    
    // Wait for all workers to complete
    for (i, handle) in worker_handles.into_iter().enumerate() {
        if let Err(e) = handle.await {
            error!("Worker {} panicked: {}", i, e);
        }
    }
    
    // Print performance statistics
    let total_time = scan_start.elapsed();
    let targets_count = config.targets.len();
    let rate = targets_count as f64 / total_time.as_secs_f64();
    
    info!("Scan completed: {} targets in {:.2?} ({:.2} targets/second)", 
         targets_count,
         total_time,
         rate);
    
    // Return results
    match Arc::try_unwrap(results) {
        Ok(mutex) => mutex.into_inner().unwrap_or_default(),
        Err(_) => {
            error!("Failed to unwrap results Arc");
            Vec::new()
        },
    }
}

// Helper function to process a single target
async fn process_target(
    socket: &Socket,
    target: Target,
    timeout_duration: Duration,
    retry_count: u8,
    consecutive_failures: &mut u32,
) -> PortState {
    let mut state = PortState::Filtered;
    
    // Try multiple times for reliability
    for attempt in 0..retry_count {
        if *consecutive_failures > 100 {
            // If we're having many failures, add a small delay
            // This can help reduce system resource contention
            if attempt > 0 {
                trace!("High failure rate detected ({}), adding delay", *consecutive_failures);
                sleep(Duration::from_millis(5)).await;
            }
        }
        
        // Generate a random source port to help identify our packets
        let src_port = rand::thread_rng().gen_range(49152..65535);
        
        // Handle IPv4 targets with optimized path
        if let IpAddr::V4(target_ipv4) = target.addr {
            // Create and send SYN packet
            if let Some(syn_packet) = create_syn_packet(src_port, target.port, target_ipv4) {
                if send_packet(socket, &syn_packet, target_ipv4).is_ok() {
                    // Wait for response with timeout
                    match receive_response(socket, src_port, target.port, target_ipv4, timeout_duration).await {
                        Ok(Some(response_state)) => {
                            state = response_state;
                            *consecutive_failures = 0;
                            break; // We got a definitive answer
                        }
                        Ok(None) => {
                            // No response, keep as filtered
                            if attempt == retry_count - 1 {
                                trace!("No response from {}:{} after {} attempts", target_ipv4, target.port, retry_count);
                                *consecutive_failures = consecutive_failures.saturating_add(1);
                            }
                        }
                        Err(e) => {
                            debug!("Error receiving response from {}:{}: {}", target_ipv4, target.port, e);
                            *consecutive_failures = consecutive_failures.saturating_add(1);
                            // Error receiving, continue to next attempt
                        }
                    }
                } else {
                    debug!("Failed to send packet to {}:{}", target_ipv4, target.port);
                    *consecutive_failures = consecutive_failures.saturating_add(1);
                }
            }
        } else {
            trace!("IPv6 address encountered: {}, skipping", target.addr);
        }
        
        // Only sleep between retries if not the last attempt
        if attempt < retry_count - 1 && *consecutive_failures < 100 {
            // Minimal delay between retries
            tokio::task::yield_now().await;
        }
    }
    
    trace!("Port {}:{} scan result: {:?}", target.addr, target.port, state);
    state
}

// Helper function to create a TCP SYN packet
fn create_syn_packet(src_port: u16, dst_port: u16, dst_ip: Ipv4Addr) -> Option<Vec<u8>> {
    // Create buffer for IP + TCP packet
    let mut buffer = vec![0u8; SYN_PACKET_SIZE];
    let mut tcp_buffer = &mut buffer[20..]; // Skip IP header space
    let mut tcp_packet = MutableTcpPacket::new(tcp_buffer).unwrap();
    
    // Fill TCP header
    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
    tcp_packet.set_sequence(rand::thread_rng().gen());
    tcp_packet.set_window(64240);
    tcp_packet.set_data_offset(5); // 5 32-bit words = 20 bytes
    tcp_packet.set_flags(TcpFlags::SYN);
    
    // Set some optimal TCP options for faster scanning
    tcp_packet.set_urgent_ptr(0);
    tcp_packet.set_acknowledgement(0);
    
    // Calculate checksum - we need our local IP to create proper checksum
    let source_ip = get_local_ipv4().unwrap_or_else(|| Ipv4Addr::new(127, 0, 0, 1));
    let checksum = pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), 
                                                  &source_ip, 
                                                  &dst_ip);
    tcp_packet.set_checksum(checksum);
    
    Some(buffer)
}

// Get the local IPv4 address (cached to avoid repeated lookups)
fn get_local_ipv4() -> Option<Ipv4Addr> {
    // Use a static/lazy value to cache the result
    use std::sync::Once;
    use std::net::UdpSocket;
    
    static mut LOCAL_IP: Option<Ipv4Addr> = None;
    static INIT: Once = Once::new();
    
    unsafe {
        INIT.call_once(|| {
            // This is a common trick: create a UDP socket to a public IP (doesn't actually send data)
            // to determine which local interface would be used
            if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
                if socket.connect("8.8.8.8:80").is_ok() {
                    if let Ok(addr) = socket.local_addr() {
                        if let std::net::SocketAddr::V4(addr) = addr {
                            LOCAL_IP = Some(*addr.ip());
                        }
                    }
                }
            }
        });
        
        LOCAL_IP
    }
}

// Helper function to send a raw packet
fn send_packet(socket: &Socket, packet: &[u8], dst_ip: Ipv4Addr) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    use std::net::SocketAddrV4;
    
    // Use a static socket address to avoid repeated allocations
    let addr = SocketAddrV4::new(dst_ip, 0);
    let sock_addr = socket2::SockAddr::from(addr);
    
    // More efficient send - try to send the entire packet at once
    match socket.send_to(packet, &sock_addr) {
        Ok(sent) if sent == packet.len() => Ok(()),
        Ok(_) => Err(Error::new(ErrorKind::Other, "Partial send")),
        Err(e) => Err(e),
    }
}

// Helper function to receive and process a response
async fn receive_response(
    socket: &Socket,
    src_port: u16,
    dst_port: u16,
    dst_ip: Ipv4Addr,
    timeout_duration: Duration,
) -> std::io::Result<Option<PortState>> {
    use std::io::{Error, ErrorKind};
    
    // Preallocated receive buffer to avoid repeated allocations
    let mut recv_buf = [MaybeUninit::<u8>::uninit(); 2048];
    let start = Instant::now();
    
    // Non-blocking polling with aggressive retry
    while start.elapsed() < timeout_duration {
        match socket.recv(&mut recv_buf) {
            Ok(size) if size > 40 => { // IP header (20) + TCP header (20) minimum
                // SAFETY: We know that the first `size` bytes are initialized
                let packet = unsafe {
                    std::slice::from_raw_parts(
                        recv_buf.as_ptr() as *const u8,
                        size
                    )
                };
                
                // Fast packet filtering
                // Check if this packet is from our target (check the source IP at offset 12..16)
                if size >= 20 {
                    let src_ip_bytes = [packet[12], packet[13], packet[14], packet[15]];
                    let received_src_ip = Ipv4Addr::new(src_ip_bytes[0], src_ip_bytes[1], src_ip_bytes[2], src_ip_bytes[3]);
                    
                    if received_src_ip == dst_ip {
                        // Get the TCP header
                        // Extract source and destination ports (TCP header starts at IP header length)
                        let ip_header_len = (packet[0] & 0x0F) * 4;
                        if size >= (ip_header_len as usize + 4) {
                            let tcp_start = ip_header_len as usize;
                            
                            // Check the destination port (our source port)
                            let received_dst_port = ((packet[tcp_start] as u16) << 8) | (packet[tcp_start + 1] as u16);
                            // Check source port (our destination port)
                            let received_src_port = ((packet[tcp_start + 2] as u16) << 8) | (packet[tcp_start + 3] as u16);
                            
                            // Verify this packet is for us
                            if received_dst_port == src_port && received_src_port == dst_port {
                                // Check the TCP flags at offset 13 in TCP header
                                if size >= (tcp_start + 13) {
                                    let flags = packet[tcp_start + 13];
                                    
                                    // SYN-ACK = port is open (0x12 = SYN | ACK)
                                    if (flags & 0x12) == 0x12 {
                                        return Ok(Some(PortState::Open));
                                    }
                                    // RST or RST-ACK = port is closed (0x04 = RST, 0x14 = RST | ACK)
                                    else if (flags & 0x04) == 0x04 {
                                        return Ok(Some(PortState::Closed));
                                    }
                                }
                            }
                        }
                    }
                }
            },
            Ok(_) => {}, // Empty or too small packet, ignore
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                // Aggressive polling with minimal sleep
                tokio::task::yield_now().await;
            },
            Err(e) => return Err(e),
        }
    }
    
    // No conclusive response within timeout
    Ok(None)
}

// Fallback method using optimized TCP connect for platforms without raw socket support
pub async fn scan_ports_tcp_connect(config: &ScanConfig) -> Vec<ScanResult> {
    use tokio::net::TcpStream;
    
    info!("Starting TCP connect scan of {} targets with batch size {}", 
          config.targets.len(), config.batch_size);
    
    // Track scan statistics for debugging
    let scan_start = Instant::now();
    let target_count = config.targets.len();
    let completed = Arc::new(AtomicUsize::new(0));
    let result_vec = Arc::new(Mutex::new(Vec::with_capacity(target_count)));
    
    // Create a channel for distributing targets to workers
    let (tx, rx) = tokio::sync::mpsc::channel::<Target>(config.batch_size.min(10000));
    
    // Wrap the receiver in an Arc<Mutex> so multiple workers can share it
    let rx = Arc::new(Mutex::new(rx));
    
    // Determine optimal worker count
    let worker_count = num_cpus::get().min(config.batch_size).max(4);
    info!("Using {} worker threads for TCP connect scan", worker_count);
    
    // Create workers
    let mut worker_handles = Vec::with_capacity(worker_count);
    for worker_id in 0..worker_count {
        let rx = Arc::clone(&rx);
        let results = Arc::clone(&result_vec);
        let completed_counter = Arc::clone(&completed);
        let timeout_duration = config.timeout;
        let rate_limit = config.rate_limit;
        
        let handle = tokio::spawn(async move {
            debug!("TCP connect worker {} starting", worker_id);
            let mut local_results = Vec::with_capacity(1000);
            let mut processed_count = 0;
            
            // Loop until channel is closed or empty
            loop {
                // Get the next target from the shared receiver
                let target = {
                    let mut rx_lock = rx.lock().unwrap();
                    match rx_lock.try_recv() {
                        Ok(target) => Some(target),
                        Err(_) => None,
                    }
                };
                
                // Break if no more targets
                let Some(target) = target else { break };
                
                let start_time = Instant::now();
                
                // Connect with timeout
                let socket_addr = std::net::SocketAddr::new(target.addr, target.port);
                trace!("Worker {}: Connecting to {}:{}", worker_id, target.addr, target.port);
                
                let state = match timeout(timeout_duration, TcpStream::connect(socket_addr)).await {
                    Ok(Ok(_)) => {
                        info!("Open port found: {}:{}", target.addr, target.port);
                        PortState::Open
                    },
                    Ok(Err(e)) => {
                        trace!("Connection to {}:{} failed: {}", target.addr, target.port, e);
                        PortState::Closed
                    },
                    Err(_) => {
                        trace!("Connection to {}:{} timed out", target.addr, target.port);
                        PortState::Filtered
                    },
                };
                
                // Store result
                local_results.push(ScanResult {
                    addr: target.addr,
                    port: target.port,
                    state,
                });
                
                // Update completed count
                processed_count += 1;
                completed_counter.fetch_add(1, Ordering::Relaxed);
                
                // Periodically flush results to shared collection
                if local_results.len() >= 1000 {
                    if let Ok(mut shared_results) = results.lock() {
                        shared_results.extend(local_results.drain(..));
                        debug!("Worker {}: Flushed batch of results", worker_id);
                    }
                }
                
                // Log periodic progress
                if processed_count % 1000 == 0 {
                    debug!("Worker {}: Processed {} targets", worker_id, processed_count);
                }
                
                // Rate limiting if configured
                if let Some(rate) = rate_limit {
                    let elapsed = start_time.elapsed();
                    let target_duration = Duration::from_secs_f64(1.0 / rate as f64);
                    if elapsed < target_duration {
                        let sleep_duration = target_duration - elapsed;
                        trace!("Worker {}: Rate limiting, sleeping for {:?}", worker_id, sleep_duration);
                        sleep(sleep_duration).await;
                    }
                }
                
                // Yield to other tasks periodically
                if local_results.len() % 10 == 0 {
                    tokio::task::yield_now().await;
                }
            }
            
            // Final flush of local results
            if !local_results.is_empty() {
                if let Ok(mut shared_results) = results.lock() {
                    debug!("Worker {}: Final flush of {} results", worker_id, local_results.len());
                    shared_results.extend(local_results);
                }
            }
            
            info!("TCP connect worker {} completed, processed {} targets", worker_id, processed_count);
        });
        
        worker_handles.push(handle);
    }
    
    // Send targets to workers differently since we're using a mutex-protected channel
    info!("Sending targets to TCP connect workers");
    let mut sent_count = 0;
    for target in &config.targets {
        if tx.send(*target).await.is_err() {
            error!("Failed to send target to TCP connect worker");
            break;
        }
        
        sent_count += 1;
        
        // Log progress periodically
        if sent_count % 5000 == 0 {
            debug!("Sent {}/{} targets to workers ({:.1}%)", 
                  sent_count, target_count, (sent_count as f64 / target_count as f64) * 100.0);
        }
        
        // Periodically yield for very large scans
        if target_count > 10000 && sent_count % 1000 == 0 {
            tokio::task::yield_now().await;
        }
    }
    
    // Drop the sender to signal completion
    drop(tx);
    info!("All targets sent to TCP connect workers, waiting for completion");
    
    // Report progress for large scans
    if target_count > 1000 {
        tokio::spawn(async move {
            let mut last_completed = 0;
            while scan_start.elapsed() < Duration::from_secs(3600) {  // 1 hour max timeout
                sleep(Duration::from_secs(2)).await;
                let current = completed.load(Ordering::Relaxed);
                if current >= target_count || current == last_completed {
                    break;
                }
                
                let progress = (current as f64 / target_count as f64) * 100.0;
                let rate = (current - last_completed) as f64 / 2.0; // per second
                
                info!("TCP connect progress: {:.1}% ({}/{}) - {:.1} ports/sec", 
                     progress, current, target_count, rate);
                
                last_completed = current;
            }
        });
    }
    
    // Wait for all workers to complete
    for (idx, handle) in worker_handles.into_iter().enumerate() {
        if let Err(e) = handle.await {
            error!("TCP connect worker {} panicked: {}", idx, e);
        }
    }
    
    // Print performance summary
    let total_time = scan_start.elapsed();
    let scan_rate = target_count as f64 / total_time.as_secs_f64();
    
    info!("TCP Connect scan completed: {} targets in {:.2?} ({:.2} targets/second)",
         target_count,
         total_time,
         scan_rate);
    
    // Return results
    match Arc::try_unwrap(result_vec) {
        Ok(mutex) => mutex.into_inner().unwrap_or_default(),
        Err(_) => {
            error!("Failed to unwrap results Arc in TCP connect scanner");
            Vec::new()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::time::Duration;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_scan_ports_example() {
        // This test requires a local service listening on port 80 or will show it as closed/filtered.
        let config = ScanConfig {
            targets: vec![
                Target { addr: IpAddr::from_str("127.0.0.1").unwrap(), port: 80 },
                Target { addr: IpAddr::from_str("127.0.0.1").unwrap(), port: 8080 },
            ],
            timeout: Duration::from_secs(1),
            batch_size: 10,
            rate_limit: None,
            retry_count: 2,
        };

        // Try SYN scan first, fall back to TCP connect if needed
        let results = scan_ports(&config).await;
        if results.is_empty() {
            eprintln!("SYN scan failed, falling back to TCP connect scan");
            let results = scan_ports_tcp_connect(&config).await;
            println!("Scan results: {:?}", results);
            assert!(!results.is_empty());
        } else {
            println!("Scan results: {:?}", results);
            assert!(!results.is_empty());
        }
    }
    
    #[tokio::test(flavor = "multi_thread")]
    async fn test_scan_port_range() {
        // This test scans a range of ports on localhost
        println!("Testing high-performance port range scan");
        std::env::set_var("RUST_LOG", "debug");
        env_logger::init();
        
        // Define a larger port range to better demonstrate performance
        const PORT_START: u16 = 1;
        const PORT_END: u16 = 10000;
        
        // Create targets for the port range
        let localhost = IpAddr::from_str("127.0.0.1").unwrap();
        let mut targets = Vec::with_capacity((PORT_END - PORT_START + 1) as usize);
        
        for port in PORT_START..=PORT_END {
            targets.push(Target { 
                addr: localhost, 
                port 
            });
        }
        
        // Configure the scan with optimized parameters
        let config = ScanConfig {
            targets,
            timeout: Duration::from_millis(100),  // Faster timeout
            batch_size: 1000,  // Larger batch size
            rate_limit: None,  // No rate limiting for maximum performance
            retry_count: 1,    // Single attempt for speed testing
        };
        
        // Run both scan methods for comparison
        // First, raw socket (SYN) scan
        println!("\n=== Testing SYN scan performance ===");
        let start = std::time::Instant::now();
        let results_syn = scan_ports(&config).await;
        let duration_syn = start.elapsed();
        
        if !results_syn.is_empty() {
            // Calculate statistics for SYN scan
            let open_ports = results_syn.iter().filter(|r| matches!(r.state, PortState::Open)).count();
            let closed_ports = results_syn.iter().filter(|r| matches!(r.state, PortState::Closed)).count();
            let filtered_ports = results_syn.iter().filter(|r| matches!(r.state, PortState::Filtered)).count();
            
            println!("SYN scan results: {} open, {} closed, {} filtered", open_ports, closed_ports, filtered_ports);
            println!("SYN scan performance: {} ports in {:.2?} ({:.2} ports/second)", 
                     results_syn.len(), 
                     duration_syn,
                     results_syn.len() as f64 / duration_syn.as_secs_f64());
        } else {
            println!("SYN scan failed - likely insufficient permissions");
        }
        
        // Next, TCP connect scan
        println!("\n=== Testing TCP connect scan performance ===");
        let start = std::time::Instant::now();
        let results_tcp = scan_ports_tcp_connect(&config).await;
        let duration_tcp = start.elapsed();
        
        // Calculate statistics for TCP connect scan
        let open_ports = results_tcp.iter().filter(|r| matches!(r.state, PortState::Open)).count();
        let closed_ports = results_tcp.iter().filter(|r| matches!(r.state, PortState::Closed)).count();
        let filtered_ports = results_tcp.iter().filter(|r| matches!(r.state, PortState::Filtered)).count();
        
        println!("TCP connect scan results: {} open, {} closed, {} filtered", open_ports, closed_ports, filtered_ports);
        println!("TCP connect scan performance: {} ports in {:.2?} ({:.2} ports/second)", 
                 results_tcp.len(), 
                 duration_tcp,
                 results_tcp.len() as f64 / duration_tcp.as_secs_f64());
        
        // Print open ports
        if open_ports > 0 {
            println!("\nOpen ports found:");
            for result in results_tcp.iter().filter(|r| matches!(r.state, PortState::Open)) {
                println!("  - Port {}", result.port);
            }
        }
        
        // Verify correct number of results
        assert_eq!(results_tcp.len(), (PORT_END - PORT_START + 1) as usize, 
                   "Number of results should match the port range size");
    }
}


pub mod testx {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::time::Duration;

    pub async fn test_scan_port_range() {
        // This test scans a range of ports on localhost
        println!("Testing high-performance port range scan");
        std::env::set_var("RUST_LOG", "debug");
        env_logger::init();
        
        // Define a larger port range to better demonstrate performance
        const PORT_START: u16 = 1;
        const PORT_END: u16 = 10000;
        
        // Create targets for the port range
        let localhost = IpAddr::from_str("127.0.0.1").unwrap();
        let mut targets = Vec::with_capacity((PORT_END - PORT_START + 1) as usize);
        
        for port in PORT_START..=PORT_END {
            targets.push(Target { 
                addr: localhost, 
                port 
            });
        }
        
        // Configure the scan with optimized parameters
        let config = ScanConfig {
            targets,
            timeout: Duration::from_millis(100),  // Faster timeout
            batch_size: 1000,  // Larger batch size
            rate_limit: None,  // No rate limiting for maximum performance
            retry_count: 1,    // Single attempt for speed testing
        };
        
        // Run both scan methods for comparison
        // First, raw socket (SYN) scan
        println!("\n=== Testing SYN scan performance ===");
        let start = std::time::Instant::now();
        let results_syn = scan_ports(&config).await;
        let duration_syn = start.elapsed();
        
        if !results_syn.is_empty() {
            // Calculate statistics for SYN scan
            let open_ports = results_syn.iter().filter(|r| matches!(r.state, PortState::Open)).count();
            let closed_ports = results_syn.iter().filter(|r| matches!(r.state, PortState::Closed)).count();
            let filtered_ports = results_syn.iter().filter(|r| matches!(r.state, PortState::Filtered)).count();
            
            println!("SYN scan results: {} open, {} closed, {} filtered", open_ports, closed_ports, filtered_ports);
            println!("SYN scan performance: {} ports in {:.2?} ({:.2} ports/second)", 
                     results_syn.len(), 
                     duration_syn,
                     results_syn.len() as f64 / duration_syn.as_secs_f64());
        } else {
            println!("SYN scan failed - likely insufficient permissions");
        }
        
        // Next, TCP connect scan
        println!("\n=== Testing TCP connect scan performance ===");
        let start = std::time::Instant::now();
        let results_tcp = scan_ports_tcp_connect(&config).await;
        let duration_tcp = start.elapsed();
        
        // Calculate statistics for TCP connect scan
        let open_ports = results_tcp.iter().filter(|r| matches!(r.state, PortState::Open)).count();
        let closed_ports = results_tcp.iter().filter(|r| matches!(r.state, PortState::Closed)).count();
        let filtered_ports = results_tcp.iter().filter(|r| matches!(r.state, PortState::Filtered)).count();
        
        println!("TCP connect scan results: {} open, {} closed, {} filtered", open_ports, closed_ports, filtered_ports);
        println!("TCP connect scan performance: {} ports in {:.2?} ({:.2} ports/second)", 
                 results_tcp.len(), 
                 duration_tcp,
                 results_tcp.len() as f64 / duration_tcp.as_secs_f64());
        
        // Print open ports
        if open_ports > 0 {
            println!("\nOpen ports found:");
            for result in results_tcp.iter().filter(|r| matches!(r.state, PortState::Open)) {
                println!("  - Port {}", result.port);
            }
        }
        
        // Verify correct number of results
        assert_eq!(results_tcp.len(), (PORT_END - PORT_START + 1) as usize, 
                   "Number of results should match the port range size");
    }
}