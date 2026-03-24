//main.rs
//Author: iss4cf0ng/ISSAC
//GitHub: https://github.com/iss4cf0ng/IronPE

#![allow(non_snake_case)]

mod loader;
mod logger;
mod pe_structures;

use loader::{X64PeLoader, X86PeLoader};
use logger::{log_error, log_info, log_ok};
use std::env;
use std::fs;
use std::path::Path;

use crate::loader::load_x64;
use crate::loader::load_x86;

const BANNER: &str = r#"
  _        (`-')            <-. (`-')_  _  (`-') (`-')  _ 
 (_)    <-.(OO )      .->      \( OO) ) \-.(OO ) ( OO).-/ 
 ,-(`-'),------,)(`-')----. ,--./ ,--/  _.'    \(,------. 
 | ( OO)|   /`. '( OO).-.  '|   \ |  | (_...--'' |  .---' 
 |  |  )|  |_.' |( _) | |  ||  . '|  |)|  |_.' |(|  '--.  
(|  |_/ |  .   .' \|  |)|  ||  |\    | |  .___.' |  .--'  
 |  |'->|  |\  \   '  '-'  '|  | \   | |  |      |  `---. 
 `--'   `--' '--'   `-----' `--'  `--' `--'      `------' 
"#;

const DESCRIPTION: &str = "Author: iss4cf0ng/ISSAC\nGitHub: https://github.com/iss4cf0ng/IronPE";

const USAGE: &str = "Example:
\tIronPE.exe --x86 <FilePath>
\tIronPE.exe --x64 <FilePath>
\tIronPE.exe --coffee
";

const COFFEE: &str = r#"
    (  )   (   )  )
     ) (   )  (  (
     ( )  (    ) )
     _____________
    <_____________> ___
    |             |/ _ \
    |               | | |
    |               |_| |
 ___|             |\___/
/    \___________/    \
\_____________________/
"#;

fn main() {
    #[cfg(windows)]
    {
        use windows::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, SetConsoleMode,
            ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_OUTPUT_HANDLE,
        };
        unsafe {
            let handle = GetStdHandle(STD_OUTPUT_HANDLE).unwrap();
            let mut mode = windows::Win32::System::Console::CONSOLE_MODE(0);
            let _ = GetConsoleMode(handle, &mut mode);
            let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }

    println!("{}", BANNER);
    println!("{}", DESCRIPTION);

    let arch = if cfg!(target_pointer_width = "64") {
        "x64"
    } else {
        "x86"
    };
    log_info(&format!("The current process architecture is: {}", arch));

    let args: Vec<String> = env::args().collect();

    //Validate argument counts
    let valid = args.len() >= 3 || (args.len() == 2 && args[1] == "--coffee");
    if !valid {
        println!("{}", USAGE);
        return;
    }

    if let Err(e) = run(&args) {
        log_error(&e);
    }
}

fn run(args: &[String]) -> Result<(), String> {
    match args[1].as_str() {
        "--coffee" => {
            println!("{}", COFFEE);
            Ok(())
        }

        "--x86" => {
            log_info("Action => x86 loading...");
            
            if cfg!(target_pointer_width = "64") {
                return Err(
                    "Current process is x64, cannot load an x86 PE from a 64-bit process.".to_string(),
                );
            }

            let path = &args[2];
            let bytes = read_file(path)?;

            let pe = X86PeLoader::new(bytes)?;
            if !pe.is_32bit() {
                return Err("This is not an x86 (PE32) file.".to_string());
            }

            let image_base = pe.optional_header.image_base;
            
            log_ok(&format!("Image base = {:#X}", image_base));

            return load_x86(&pe);
        }

        "--x64" => {
            log_info("Action => x64 loading...");

            if cfg!(target_pointer_width = "32") {
                return Err(
                    "Current process is x86, cannot load an x64 PE from a 32-bit process.".to_string(),
                );
            }

            let path = &args[2];
            let bytes = read_file(path)?;
            
            let pe = X64PeLoader::new(bytes)?;
            if pe.is_32bit_header() {
                return Err("This is not an x64 PE file.".to_string());
            }

            let image_base = pe.optional_header64.image_base;
            
            log_ok(&format!("Image base = {:#X}", image_base));

            return load_x64(&pe);
        }

        other => Err(format!("Unknown command: {}", other)),
    }
}

/* 
fn read_file(path: &str) -> Result<Vec<u8>, String> {
    if !std::path::Path::new(path).exists() {
        return Err(format!("File not found: {}", path));
    }

    let bytes = fs::read(path).map_err(|e| format!("Failed to read file '{}: {}'", path, e))?;
    log_ok(&format!("Read file successfully. Length: {}", bytes.len()));

    return Ok(bytes);
}

*/ 

fn read_file(path: &str) -> Result<Vec<u8>, String> {
    // 🔥 DETECT URL
    if path.starts_with("http://") || path.starts_with("https://") {
        return fetch_from_url(path);
    }

    // fallback ke file lokal (kode lama)
    if !Path::new(path).exists() {
        return Err(format!("File not found: {}", path));
    }

    let bytes = fs::read(path)
        .map_err(|e| format!("Failed to read file '{}': {}", path, e))?;

    log_ok(&format!("Read file successfully. Length: {}", bytes.len()));
    Ok(bytes)
}

fn fetch_from_url(url: &str) -> Result<Vec<u8>, String> {
    let resp = reqwest::blocking::get(url)
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("HTTP error: {}", resp.status()));
    }

    let bytes = resp
        .bytes()
        .map_err(|e| format!("Failed to read response: {}", e))?;

    log_ok(&format!("Downloaded from URL. Length: {}", bytes.len()));
    Ok(bytes.to_vec())
}