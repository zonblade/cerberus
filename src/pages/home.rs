use std::io::{self, Write};

use crossterm::{cursor, execute};

pub fn draw_home<W: Write>(stdout: &mut W) -> io::Result<()> {
    execute!(
        stdout,
        cursor::MoveTo(0, 0),
        crossterm::style::Print("Home Page"),
        cursor::MoveTo(0, 1),
        crossterm::style::Print("Press 's' to go to Settings, 'q' to quit.")
    )
}
