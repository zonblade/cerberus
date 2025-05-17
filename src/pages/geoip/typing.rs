use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct GeoIPResponse {
    pub accuracy: Option<i32>,
    pub area_code: Option<String>,
    pub asn: Option<i32>,
    pub continent_code: Option<String>,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub country_code3: Option<String>,
    pub ip: String,
    pub latitude: Option<String>,
    pub longitude: Option<String>,
    pub organization: Option<String>,
    pub organization_name: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub timezone: Option<String>,
}

pub struct InputState {
    pub input_text: String,
    pub cursor_position: usize,
    pub is_input_active: bool,
    pub is_loading: bool,
}

impl InputState {
    pub fn new() -> Self {
        Self {
            input_text: String::new(),
            cursor_position: 0,
            is_input_active: true,
            is_loading: false,
        }
    }

    pub fn insert(&mut self, c: char) {
        if !self.is_loading {
            self.input_text.insert(self.cursor_position, c);
            self.cursor_position += 1;
        }
    }

    pub fn backspace(&mut self) {
        if !self.is_loading && self.cursor_position > 0 {
            self.cursor_position -= 1;
            self.input_text.remove(self.cursor_position);
        }
    }

    pub fn delete(&mut self) {
        if !self.is_loading && self.cursor_position < self.input_text.len() {
            self.input_text.remove(self.cursor_position);
        }
    }

    pub fn move_cursor_left(&mut self) {
        if !self.is_loading && self.cursor_position > 0 {
            self.cursor_position -= 1;
        }
    }

    pub fn move_cursor_right(&mut self) {
        if !self.is_loading && self.cursor_position < self.input_text.len() {
            self.cursor_position += 1;
        }
    }

    pub fn clear(&mut self) {
        self.input_text.clear();
        self.cursor_position = 0;
        self.is_loading = false;
    }
}
