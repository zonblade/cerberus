use std::io::{self, Write};

use crossterm::{cursor, execute};

pub fn draw_home<W: Write>(stdout: &mut W) -> io::Result<()> {
    execute!(
        stdout,
        cursor::MoveTo(0, 1) ,crossterm::style::Print("    .  :  :  :   :  :  :: .:   @@   ::   @@   .:  :  :  .   :  .  :   .   "),
        cursor::MoveTo(0, 2) ,crossterm::style::Print("                              @@@@      @@@@                              "),
        cursor::MoveTo(0, 3) ,crossterm::style::Print("                             @@@ @@    @@@@@@                             "),
        cursor::MoveTo(0, 4) ,crossterm::style::Print("                             @@@ @@@@@@@@ @@@                             "),
        cursor::MoveTo(0, 5) ,crossterm::style::Print("  :  .   :  :  .      .  .   @@  CERBERUS  @@   .  :      .  .  .   .  .  "),
        cursor::MoveTo(0, 6) ,crossterm::style::Print("    .  :  :  :.  :  :  :: .: @@@@@@@@@@@@@@@@  :  :  :  .   .  :  :   .   "),
        cursor::MoveTo(0, 7) ,crossterm::style::Print("#-------------------------------------------------------------------------#"),

        
        cursor::MoveTo(0, 21), crossterm::style::Print("#------------------------------------------------------------------------#"),
        cursor::MoveTo(0, 22), crossterm::style::Print("# [q] Quit [s] Settings || use your mouse, or arrow to select the tools  #"),
        cursor::MoveTo(0, 23), crossterm::style::Print("#------------------------------------------------------------------------#")
    )
}