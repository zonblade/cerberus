mod pages;
mod route;
mod visor;
mod elements;

use crossterm::{
    cursor,
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use route::run_app;
use std::io;
use log::LevelFilter;
use env_logger::Builder;

// fn main() -> Result<(), Box<dyn std::error::Error>> {    
//     // Initialize logger
//     init_logger();
    
//     enable_raw_mode()?;
    
//     let mut stdout = io::stdout();
//     execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
//     let mut stdout = io::stdout();
//     stdout.execute(cursor::Hide)?;
    
//     let res = run_app(&mut stdout);
    
//     disable_raw_mode()?;

//     execute!(
//         stdout,
//         LeaveAlternateScreen,
//         DisableMouseCapture,
//         cursor::Show
//     )?;

//     if let Err(err) = res {
//         println!("{:?}", err)
//     }

//     Ok(())
// }


// create tokio main
#[tokio::main]
async fn main() {
    init_logger();
    
    pages::network::scanner::scan_example();
    // pages::network::scanner_syn::scan_example().await;
}



// Initialize the logger with appropriate settings
fn init_logger() {
    println!("Testing high-performance port range scan");
    std::env::set_var("RUST_LOG", "debug");
}
