use super::typing::GeoIPResponse;
use reqwest::blocking::Client;
use std::time::Duration;

const BASE_URL: &str = "https://get.geojs.io/v1/ip/geo";

pub fn get_geoip_data(ip: Option<&str>) -> Result<GeoIPResponse, String> {
    let client = Client::new();
    
    // Construct URL based on whether an IP is provided
    let url = match ip {
        Some(ip_addr) if !ip_addr.is_empty() => format!("{}/{}.json", BASE_URL, ip_addr),
        _ => format!("{}.json", BASE_URL), // Default to current IP if none provided
    };
    
    // Make the request with a timeout
    match client.get(&url)
        .timeout(Duration::from_secs(10))
        .send() {
            Ok(response) => {
                if response.status().is_success() {
                    match response.json::<GeoIPResponse>() {
                        Ok(data) => Ok(data),
                        Err(e) => Err(format!("Failed to parse response: {}", e)),
                    }
                } else {
                    Err(format!("API request failed with status: {}", response.status()))
                }
            },
            Err(e) => Err(format!("Request error: {}", e)),
        }
}

// Function to check if a string is a valid IP address
pub fn is_valid_ip(ip: &str) -> bool {
    let octets: Vec<&str> = ip.split('.').collect();
    
    if octets.len() != 4 {
        return false;
    }
    
    for octet in octets {
        match octet.parse::<u8>() {
            Ok(_) => continue,
            Err(_) => return false,
        }
    }
    
    true
}

// Function to check if a string is a valid domain
pub fn is_valid_domain(domain: &str) -> bool {
    // Basic check for now, can be enhanced
    domain.contains('.')
}
