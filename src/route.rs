use crossterm::{
    execute,
    terminal::{Clear, ClearType},
};
use std::io::{self, Write};

use crate::pages::{
    home::draw_home, home_events::handle_home_events, settings::draw_settings,
    settings_events::handle_settings_events, settings_typing::SettingsMenu,
};

pub enum Page {
    Home,
    Settings(SettingsMenu),
}

pub enum Transition {
    To(Page),
    Quit,
    Refresh
}

pub fn run_app<W: Write>(stdout: &mut W) -> io::Result<()> {
    let mut current_page = Page::Home;

    loop {
        // Clear the screen
        execute!(stdout, Clear(ClearType::All))?;

        // Handle events
        match current_page {
            Page::Home => match handle_home_events(stdout)? {
                Transition::To(page) => current_page = page,
                Transition::Quit => return Ok(()),
                Transition::Refresh => draw_home(stdout)?,
            },
            Page::Settings(ref mut submenu) => match handle_settings_events(stdout, submenu)? {
                Transition::To(page) => current_page = page,
                Transition::Quit => return Ok(()),
                Transition::Refresh => draw_settings(stdout, submenu)?,
            },
        }
    }
}
