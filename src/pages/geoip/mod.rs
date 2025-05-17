pub mod toolkit;
pub mod typing;
pub mod page;
pub mod service;
pub mod action;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType},
};
use page::{draw_geoip, draw_geoip_results, draw_input_field};
use std::io::{self, Write};

use crate::{
    elements::ui_oversize,
    route::{Page, Transition},
};

use self::{
    action::{handle_input_event, ActionResult},
    typing::{GeoIPResponse, InputState}
};

pub fn handle_geoip_events<W: Write>(stdout: &mut W) -> io::Result<Transition> {
    enable_raw_mode()?;
    execute!(stdout, EnableMouseCapture)?;

    let mut input_state = InputState::new();
    let mut geoip_result: Option<Result<GeoIPResponse, String>> = None;
    let mut query_to_load: Option<String> = None;
    let mut api_result_receiver: Option<std::sync::mpsc::Receiver<Result<GeoIPResponse, String>>> = None;

    loop {
        execute!(stdout, Clear(ClearType::All))?;
        match ui_oversize::detect(stdout) {
            Ok(Some(Transition::Quit)) => {
                disable_raw_mode()?;
                execute!(stdout, DisableMouseCapture)?;
                return Ok(Transition::Quit);
            }
            Ok(None) => {}
            Err(e) => return Err(e),
            _ => {}
        };
        
        // Handle any new query to load
        if let Some(query) = query_to_load.take() {
            // Start a new thread for API call
            let (tx, rx) = std::sync::mpsc::channel();
            api_result_receiver = Some(rx);
            
            // Clone query for thread
            let query_clone = query.clone();
            
            std::thread::spawn(move || {
                let ip_option = if query_clone.is_empty() { None } else { Some(query_clone.as_str()) };
                let result = self::service::get_geoip_data(ip_option);
                let _ = tx.send(result);
            });
        }
        
        // Check if we have a result from the API call
        if let Some(ref receiver) = api_result_receiver {
            if let Ok(result) = receiver.try_recv() {
                geoip_result = Some(result);
                input_state.is_loading = false;
                api_result_receiver = None;
            }
        }
        
        draw_geoip(stdout)?;
        draw_geoip_results(stdout, &geoip_result, input_state.is_loading)?;
        draw_input_field(stdout, &input_state)?;
        
        // Flush to ensure all content is displayed
        stdout.flush()?;

        // Use a timeout to regularly refresh the screen for cursor blinking and loading animation
        if event::poll(std::time::Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) => match key.code {
                    KeyCode::Char('q') => {
                        disable_raw_mode()?;
                        execute!(stdout, DisableMouseCapture)?;
                        return Ok(Transition::Quit);
                    }
                    KeyCode::Char('h') => {
                        disable_raw_mode()?;
                        execute!(stdout, DisableMouseCapture)?;
                        return Ok(Transition::To(Page::Home));
                    }
                    KeyCode::Esc => {
                        input_state.clear();
                        geoip_result = None;
                        query_to_load = None;
                        api_result_receiver = None;
                    }
                    _ => {
                        let event_result: ActionResult = handle_input_event(&mut input_state, Event::Key(key))?;
                        match event_result {
                            ActionResult::StartLoading(query) => {
                                query_to_load = Some(query);
                            },
                            ActionResult::NewSearch(result) => {
                                geoip_result = Some(result);
                            },
                            ActionResult::None => {}
                        }
                    }
                },
                Event::Mouse(mouse_event) => {
                    let event_result: ActionResult = handle_input_event(&mut input_state, Event::Mouse(mouse_event))?;
                    match event_result {
                        ActionResult::StartLoading(query) => {
                            query_to_load = Some(query);
                        },
                        ActionResult::NewSearch(result) => {
                            geoip_result = Some(result);
                        },
                        ActionResult::None => {}
                    }
                },
                _ => {}
            }
        }
        // If no event was available, continue the loop to redraw the screen
    }
}
