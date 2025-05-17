use std::io::{self, Write};

use crossterm::{cursor, execute, style::{self, Stylize}};

use crate::pages::{home::draw_home_header, settings_typing::SettingsMenu};
use image::{DynamicImage, Pixel, Rgba, RgbaImage};
use viuer::{print_from_file, Config};

use super::typing::{GeoIPResponse, InputState};

pub fn draw_geoip<W: Write>(stdout: &mut W) -> io::Result<()> {
    draw_home_header(stdout)?;
    draw_geoip_header(stdout)?;
    draw_geoip_footer(stdout)?;
    Ok(())
}

pub fn draw_geoip_header<W: Write>(stdout: &mut W) -> io::Result<()> {
    execute!(
        stdout,
        cursor::MoveTo(0, 08), crossterm::style::Print("# [home/geoip] GEO IP Tracker                                                            #"),
        cursor::MoveTo(0, 09), crossterm::style::Print("#------------------------------------------------------------------------------#"),
        style::SetAttribute(style::Attribute::Reset),
    )
}

pub fn draw_geoip_footer<W: Write>(stdout: &mut W) -> io::Result<()> {
    execute!(
        stdout,
        cursor::MoveTo(0, 40), crossterm::style::Print("#------------------------------------------------------------------------------#"),
        cursor::MoveTo(0, 41), crossterm::style::Print("#    [q] Quit [h] Home [Enter] Search || Check where the IP originated!        #"),
        cursor::MoveTo(0, 42), crossterm::style::Print("#------------------------------------------------------------------------------#"),
        style::SetAttribute(style::Attribute::Reset),
    )
}

pub fn draw_input_field<W: Write>(stdout: &mut W, input_state: &InputState) -> io::Result<()> {
    // Draw input field border
    execute!(
        stdout,
        cursor::MoveTo(0, 38),
        crossterm::style::Print("Enter IP or domain: "),
    )?;

    // Show loading indicator if we're waiting for API response
    if input_state.is_loading {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        
        // Create a spinner animation
        let spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let spinner = spinner_frames[(now / 100) as usize % spinner_frames.len()];
        
        execute!(
            stdout,
            style::SetForegroundColor(style::Color::Yellow),
            style::SetAttribute(style::Attribute::Bold),
            crossterm::style::Print(format!("{} Loading", spinner)),
            style::SetAttribute(style::Attribute::Reset),
            style::SetForegroundColor(style::Color::Reset),
        )?;
        
        return Ok(());
    }

    // Draw the input text with a visible cursor
    let cursor_pos = input_state.cursor_position;
    let input_text = &input_state.input_text;
    
    // Draw text before cursor
    if cursor_pos > 0 {
        execute!(stdout, crossterm::style::Print(&input_text[..cursor_pos]))?;
    }
    
    // Draw blinking cursor
    if input_state.is_input_active {
        // Get current time to create blinking effect (visible half a second, invisible half a second)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        
        if (now / 500) % 2 == 0 {
            // Cursor visible phase
            execute!(
                stdout,
                style::SetForegroundColor(style::Color::White),
                style::SetBackgroundColor(style::Color::DarkCyan),
                crossterm::style::Print(
                    if cursor_pos < input_text.len() {
                        input_text.chars().nth(cursor_pos).unwrap().to_string()
                    } else {
                        " ".to_string()
                    }
                ),
                style::SetBackgroundColor(style::Color::Reset),
                style::SetForegroundColor(style::Color::Reset),
            )?;
        } else {
            // Cursor invisible phase - just show the character normally if there is one
            if cursor_pos < input_text.len() {
                execute!(stdout, crossterm::style::Print(input_text.chars().nth(cursor_pos).unwrap().to_string()))?;
            } else {
                execute!(stdout, crossterm::style::Print(" "))?;
            }
        }
    }
    
    // Draw text after cursor
    if cursor_pos < input_text.len() {
        execute!(stdout, crossterm::style::Print(&input_text[cursor_pos+1..]))?;
    }
    
    Ok(())
}

pub fn draw_geoip_results<W: Write>(stdout: &mut W, result: &Option<Result<GeoIPResponse, String>>, is_loading: bool) -> io::Result<()> {
    if is_loading {
        // Display loading message with spinner animation
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        
        // Create a spinning animation
        let spinner_frames = ["|", "/", "-", "\\"];
        let spinner = spinner_frames[(now / 150) as usize % spinner_frames.len()];
        
        execute!(
            stdout,
            cursor::MoveTo(2, 15),
            style::SetForegroundColor(style::Color::Yellow),
            crossterm::style::Print(format!("{} Fetching GeoIP information... Please wait.", spinner)),
            cursor::MoveTo(2, 17),
            crossterm::style::Print("This may take a few seconds."),
            style::SetForegroundColor(style::Color::Reset),
        )?;
        return Ok(());
    }

    match result {
        Some(Ok(data)) => {
            // Display the successful GeoIP data
            execute!(
                stdout,
                cursor::MoveTo(2, 11), crossterm::style::Print(format!("IP Address:      {}", data.ip)),
                cursor::MoveTo(2, 12), crossterm::style::Print(format!("Location:        {} {}", 
                    data.city.as_deref().unwrap_or("-"), 
                    data.region.as_deref().unwrap_or("-")
                )),
                cursor::MoveTo(2, 13), crossterm::style::Print(format!("Country:         {} ({})", 
                    data.country.as_deref().unwrap_or("-"), 
                    data.country_code.as_deref().unwrap_or("-")
                )),
                cursor::MoveTo(2, 14), crossterm::style::Print(format!("Continent:       {}", 
                    data.continent_code.as_deref().unwrap_or("-")
                )),
                cursor::MoveTo(2, 16), crossterm::style::Print(format!("Coordinates:     {}, {}", 
                    data.latitude.as_deref().unwrap_or("-"), 
                    data.longitude.as_deref().unwrap_or("-")
                )),
                cursor::MoveTo(2, 17), crossterm::style::Print(format!("Timezone:        {}", 
                    data.timezone.as_deref().unwrap_or("-")
                )),
                cursor::MoveTo(2, 19), crossterm::style::Print(format!("Organization:    {}", 
                    data.organization_name.as_deref().unwrap_or("-")
                )),
                cursor::MoveTo(2, 20), crossterm::style::Print(format!("ASN:             {}", 
                    data.asn.map(|a| a.to_string()).unwrap_or("-".to_string())
                )),
            )?;
        },
        Some(Err(error)) => {
            // Display the error message
            execute!(
                stdout,
                cursor::MoveTo(2, 11),
                style::SetForegroundColor(style::Color::Red),
                crossterm::style::Print(format!("Error: {}", error)),
                style::SetForegroundColor(style::Color::White),
            )?;
        },
        None => {
            // Initial state - provide instructions
            execute!(
                stdout,
                cursor::MoveTo(2, 15),
                crossterm::style::Print("Enter an IP address or domain name and press Enter to lookup GeoIP information."),
                cursor::MoveTo(2, 16),
                crossterm::style::Print("Leave empty to lookup your current IP address."),
            )?;
        }
    }
    
    Ok(())
}

pub fn draw_maps_display<W: Write>(stdout: &mut W)-> io::Result<()>{
    execute!(stdout)
}