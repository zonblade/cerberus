use std::io::{self, Write};

use crossterm::{
    cursor,
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, MouseButton, MouseEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType},
};

use crate::route::{Page, SettingsMenu, Transition};

const VISIBLE_ROWS: usize = 13;

pub fn handle_home_events<W: Write>(stdout: &mut W) -> io::Result<Transition> {
    enable_raw_mode()?;
    execute!(stdout, EnableMouseCapture)?;

    let content: Vec<String> = (1..=25).map(|i| format!("Line {}", i)).collect();
    let mut start_index = 0;
    let mut active_index = 0;

    loop {
        // Clear the screen and render the visible window
        for i in 0..VISIBLE_ROWS {
            if let Some(line) = content.get(start_index + i) {
                execute!(stdout, cursor::MoveTo(0, (i as u16)+8))?;
                if i == active_index {
                    writeln!(stdout, "> {}", line)?;
                } else {
                    writeln!(stdout, "  {}", line)?;
                }
            }
        }

        match event::read()? {
            Event::Key(key) => match key.code {
                KeyCode::Char('q') => {
                    disable_raw_mode()?;
                    execute!(stdout, DisableMouseCapture)?;
                    return Ok(Transition::Quit);
                }
                KeyCode::Char('s') => {
                    disable_raw_mode()?;
                    execute!(stdout, DisableMouseCapture)?;
                    return Ok(Transition::To(Page::Settings(SettingsMenu::General)));
                }
                KeyCode::Up => {
                    if active_index > 0 {
                        active_index -= 1;
                    } else if start_index > 0 {
                        start_index -= 1;
                    }
                }
                KeyCode::Down => {
                    if active_index < VISIBLE_ROWS - 1 && active_index < content.len() - 1 {
                        active_index += 1;
                    } else if start_index + VISIBLE_ROWS < content.len() {
                        start_index += 1;
                    }
                }
                _ => {}
            },
            Event::Mouse(mouse_event) => match mouse_event.kind {
                MouseEventKind::Down(MouseButton::Left) => {
                    // Calculate the row index based on the mouse click position
                    let row = mouse_event.row as usize;
                    if row >= 8 && row < 8 + VISIBLE_ROWS {
                        let relative_row = row - 8;
                        if relative_row < content.len() {
                            active_index = relative_row;
                        }
                    }
                }
                MouseEventKind::ScrollUp => {
                    if active_index > 0 {
                        active_index -= 1;
                    } else if start_index > 0 {
                        start_index -= 1;
                    }
                }
                MouseEventKind::ScrollDown => {
                    if active_index < VISIBLE_ROWS - 1 && active_index < content.len() - 1 {
                        active_index += 1;
                    } else if start_index + VISIBLE_ROWS < content.len() {
                        start_index += 1;
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }
}
