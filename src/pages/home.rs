use std::io::{self, Write};

use crossterm::{cursor, execute};

pub fn draw_home<W: Write>(stdout: &mut W) -> io::Result<()> {
    execute!(
        stdout,
        cursor::MoveTo(0, 1) ,crossterm::style::Print("    .  :  :  :   :  :  :: .:   @@   ::   @@   .:  :  :  .   :  .  :   .   "),
        cursor::MoveTo(0, 2) ,crossterm::style::Print("                              @@@@      @@@@                              "),
        cursor::MoveTo(0, 3) ,crossterm::style::Print("                             @@@ @@    @@@@@@                             "),
        cursor::MoveTo(0, 4) ,crossterm::style::Print("                             @@@ @@@@@@@@ @@@                             "),
        cursor::MoveTo(0, 5) ,crossterm::style::Print("  :  .   :  :  .      .  .   @@@@@@@@@@@@@@@@   .  :      .  .  .   .  .  "),
        cursor::MoveTo(0, 6) ,crossterm::style::Print("    .  :  :  :.  :  :  :: .: @@@@@@@@@@@@@@@@  :  :  :  .   .  :  :   .   "),
        cursor::MoveTo(0, 7) ,crossterm::style::Print("  .  .   :  .  .      .  .   @@@@@@@@@@:@@@@@   .  .      .  .  .   :  .  "),
        cursor::MoveTo(0, 8) ,crossterm::style::Print("    .  :  :  :    @    .. .: @@@@ @@@@@@ @@@@  :  .    @    .  .  .   .   "),
        cursor::MoveTo(0, 9) ,crossterm::style::Print("  .      .      @@@@          @@@@@@@@@@@@@@          @@@@             .  "),
        cursor::MoveTo(0, 10),crossterm::style::Print("            @@@@@@@ *@@@      @@@@@@@@@@@@@@      @@:  @@@@@@@            "),
        cursor::MoveTo(0, 11),crossterm::style::Print("         @@@@@@@@@@@@@@@@@   +@@@@@@@@@@@@@@@   @@@@@@@@@@@@@@@@@         "),
        cursor::MoveTo(0, 12),crossterm::style::Print("  :    @@@@@@@@@@@@@@@@@@@@@ @@@@@@@@@@@@@@@@ @@@@@@@@@@@@@@@@@@@@@    .  "),
        cursor::MoveTo(0, 13),crossterm::style::Print("      @ @ @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ @  .   "),
        cursor::MoveTo(0, 14),crossterm::style::Print("  :   @@ @@@@@@@@@@@@@@@@@ @@@@            @@@@ @@@@@@@@@@@@@@@@  @@   .  "),
        cursor::MoveTo(0, 15),crossterm::style::Print("     @@@@@@@@@@@@@@@@@@@@@@@@@@  CERBERUS  @@@@@@@@@@@@@@@@@@@@@@@@@@     "),
        cursor::MoveTo(0, 16),crossterm::style::Print("    @@@@@@@@@@@@@@@@@@@@@@ @@@@            @@@@ @@@@@@@@@@@@@@@@@@@@@@    "),
        cursor::MoveTo(0, 17),crossterm::style::Print("  @@@@@@@@@@@@@@@@@@@@@@@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  "),
        cursor::MoveTo(0, 18),crossterm::style::Print(" @@@@@@@@@@@@-  @@@@@@@@@@@ @@@@@@@@@@@@@@@@@@ @@@@@@@@@@@@@@@@@@@@@@@@@@ "),
        cursor::MoveTo(0, 19),crossterm::style::Print(" @@@@@@            @@@@@@@@@ @@@@@@@@@@@@@@@@@@@@@@@@@@            @@@@@@ "),
        cursor::MoveTo(0, 20),crossterm::style::Print("          .  :   .  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@      :  .          "),
        cursor::MoveTo(0, 21),crossterm::style::Print("  .      .  .  .   @@@@@@@@@@@ @@@@@@@@@@@@ @@@@@@@@@@@   .  .  .      .  "),
        cursor::MoveTo(0, 22),crossterm::style::Print("                      @@@@@@@@@ @@@@@@@@@@ @@@@@@@@@                      "),
        cursor::MoveTo(0, 23),crossterm::style::Print("                         @@@@@@@@*@@@@@@*@@@@@@@@                         "),
        cursor::MoveTo(0, 24),crossterm::style::Print("                             @@@@@ @@@@ @@@@@-                            "),
        cursor::MoveTo(0, 25),crossterm::style::Print("       :  :  ..  .  :  :. .       @@  @@@      .  :  .  .   .  .  .       "),
    )
}