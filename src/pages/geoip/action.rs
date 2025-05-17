use std::io::{self, Write};

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEventKind},
    terminal::{disable_raw_mode, enable_raw_mode},
};

use super::{
    service::get_geoip_data,
    typing::{GeoIPResponse, InputState},
};

pub enum ActionResult {
    None,
    StartLoading(String),
    NewSearch(Result<GeoIPResponse, String>),
}

pub fn handle_input_event(
    input_state: &mut InputState,
    event: Event,
) -> io::Result<ActionResult> {
    // If we're in loading state, only allow Escape key to cancel
    if input_state.is_loading {
        if let Event::Key(KeyEvent { code: KeyCode::Esc, .. }) = event {
            input_state.is_loading = false;
            return Ok(ActionResult::None);
        }
        return Ok(ActionResult::None);
    }

    match event {
        Event::Key(KeyEvent {
            code: KeyCode::Char(c),
            modifiers: KeyModifiers::NONE,
            ..
        }) => {
            if input_state.is_input_active {
                input_state.insert(c);
            }
            Ok(ActionResult::None)
        }
        Event::Key(KeyEvent {
            code: KeyCode::Backspace,
            ..
        }) => {
            if input_state.is_input_active {
                input_state.backspace();
            }
            Ok(ActionResult::None)
        }
        Event::Key(KeyEvent {
            code: KeyCode::Delete,
            ..
        }) => {
            if input_state.is_input_active {
                input_state.delete();
            }
            Ok(ActionResult::None)
        }
        Event::Key(KeyEvent {
            code: KeyCode::Left, ..
        }) => {
            if input_state.is_input_active {
                input_state.move_cursor_left();
            }
            Ok(ActionResult::None)
        }
        Event::Key(KeyEvent {
            code: KeyCode::Right,
            ..
        }) => {
            if input_state.is_input_active {
                input_state.move_cursor_right();
            }
            Ok(ActionResult::None)
        }
        Event::Key(KeyEvent {
            code: KeyCode::Enter,
            ..
        }) => {
            if input_state.is_input_active {
                // Set loading state but don't do the API call yet
                // to allow UI to show loading animation
                input_state.is_loading = true;
                let input = input_state.input_text.trim().to_string();
                return Ok(ActionResult::StartLoading(input));
            }
            Ok(ActionResult::None)
        }
        Event::Mouse(mouse_event) => {
            match mouse_event.kind {
                MouseEventKind::Down(MouseButton::Left) => {
                    // Calculate if the click is in the input field area
                    let row = mouse_event.row;
                    let col = mouse_event.column;
                    
                    // Input field is at row 38 and starts at column 19
                    if row == 38 && col >= 19 {
                        input_state.is_input_active = true;
                        
                        // Determine cursor position based on click position
                        let new_pos = col.saturating_sub(19) as usize;
                        input_state.cursor_position = new_pos.min(input_state.input_text.len());
                    }
                }
                _ => {}
            }
            Ok(ActionResult::None)
        }
        _ => Ok(ActionResult::None),
    }
}
