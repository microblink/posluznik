use color_print::cprintln;
use std::io::IsTerminal;

thread_local! {
    static IS_TERMINAL: bool = std::io::stdout().is_terminal();
}

pub fn print_red(text: &str) {
    IS_TERMINAL.with(|is_term| {
        if *is_term {
            cprintln!("<red>{}</red>", text);
        } else {
            println!("{}", text);
        }
    });
}

pub fn print_blue(text: &str) {
    IS_TERMINAL.with(|is_term| {
        if *is_term {
            cprintln!("<blue>{}</blue>", text);
        } else {
            println!("{}", text);
        }
    });
}

pub fn print_yellow(text: &str) {
    IS_TERMINAL.with(|is_term| {
        if *is_term {
            cprintln!("<yellow>{}</yellow>", text);
        } else {
            println!("{}", text);
        }
    });
}
