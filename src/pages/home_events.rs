use std::io::{self, Write};

use crossterm::event::{self, Event, KeyCode};

use crate::route::{Page, SettingsMenu, Transition};

pub fn handle_home_events<W: Write>(_stdout: &mut W) -> io::Result<Transition> {
    loop {
        match event::read()? {
            Event::Key(key) => match key.code {
                KeyCode::Char('q') => return Ok(Transition::Quit),
                KeyCode::Char('s') => {
                    return Ok(Transition::To(Page::Settings(SettingsMenu::General)))
                }
                _ => {}
            },
            _ => {}
        }
    }
}
