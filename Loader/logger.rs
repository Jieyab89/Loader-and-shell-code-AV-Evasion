// Author: ISSAC  https://github.com/iss4cf0ng/IronPE

use colored::Colorize;

pub fn log_ok(msg: &str) {
    println!("{} {}", "[+]".green(), msg);
}

pub fn log_info(msg: &str) {
    println!("{} {}", "[*]".cyan(), msg);
}

pub fn log_error(msg: &str) {
    println!("{} {}", "[-]".red(), msg);
}