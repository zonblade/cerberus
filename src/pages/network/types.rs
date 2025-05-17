use std::net::IpAddr;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Target {
    pub addr: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub enum PortState {
    Open,
    Closed,
    Filtered, // Or Timeout
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ScanResult {
    pub addr: IpAddr,
    pub port: u16,
    pub state: PortState,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub targets: Vec<Target>,
    pub timeout: std::time::Duration,
    pub batch_size: usize, // Number of ports to scan concurrently in a batch
    pub rate_limit: Option<usize>, // Packets per second
    pub retry_count: u8,
    // Potentially add rate, retry attempts etc. later
}
