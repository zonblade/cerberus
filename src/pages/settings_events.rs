use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{Clear, ClearType},
};
use std::io::{self, Write};

use crate::route::{Page, SettingsMenu, Transition};

use super::settings::draw_settings;

pub fn handle_settings_events<W: Write>(
    stdout: &mut W,
    submenu: &mut SettingsMenu,
) -> io::Result<Transition> {
    loop {
        match event::read()? {
            Event::Key(key) => match key.code {
                KeyCode::Char('q') => return Ok(Transition::Quit),
                KeyCode::Char('h') => return Ok(Transition::To(Page::Home)),
                KeyCode::Char('g') => *submenu = SettingsMenu::General,
                KeyCode::Char('a') => *submenu = SettingsMenu::Advanced,
                _ => {}
            },
            _ => {}
        }
        execute!(stdout, Clear(ClearType::All))?;
        draw_settings(stdout, submenu)?;
    }
}
