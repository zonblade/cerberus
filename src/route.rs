use crossterm::{
    execute,
    terminal::{Clear, ClearType},
};
use std::io::{self, Write};

use crate::pages::{
    home::draw_home, home_events::handle_home_events, settings::draw_settings,
    settings_events::handle_settings_events,
};

pub enum Page {
    Home,
    Settings(SettingsMenu),
}

pub enum SettingsMenu {
    General,
    Advanced,
}

pub enum Transition {
    To(Page),
    Quit,
}

pub fn run_app<W: Write>(stdout: &mut W) -> io::Result<()> {
    let mut current_page = Page::Home;

    loop {
        // Clear the screen
        execute!(stdout, Clear(ClearType::All))?;

        // Draw the interface
        match current_page {
            Page::Home => draw_home(stdout)?,
            Page::Settings(ref mut submenu) => draw_settings(stdout, submenu)?,
        }

        // Handle events
        match current_page {
            Page::Home => match handle_home_events(stdout)? {
                Transition::To(page) => current_page = page,
                Transition::Quit => return Ok(()),
            },
            Page::Settings(ref mut submenu) => match handle_settings_events(stdout, submenu)? {
                Transition::To(page) => current_page = page,
                Transition::Quit => return Ok(()),
            },
        }
    }
}
