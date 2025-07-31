use std::{env, path::PathBuf};

use clap::Parser;

use crate::printer::{print_red, print_yellow};

#[derive(Parser, Debug)]
#[command(author, version)]
pub struct Opts {
    #[arg(short = 'r', help = "Serve from `Release` directory.")]
    use_release: bool,

    #[arg(short = 'd', help = "Serve from `DevRelease` directory.")]
    use_dev_release: bool,

    #[arg(short = 'D', help = "Serve from `Debug` directory.")]
    use_debug: bool,

    #[arg(short = 'p', long = "port", default_value = "6931")]
    port: u16,

    #[arg(long = "input", help = "Path to the directory to serve. Defaults to the current directory.")]
    input: Option<PathBuf>,

    #[arg(long = "cross-origin", help = "Disable cross-origin isolation.")]
    cross_origin: bool,

    #[arg(long = "launch-chrome", help = "Launch Chrome")]
    launch_chrome: bool,

    #[arg(long = "chrome-path", help = "Path to Chrome executable")]
    chrome_path: Option<String>,

    #[arg(long = "launch-timeout", help = "Timeout for running the launched browser task.")]
    lauch_timeout: Option<u32>,

    #[arg(long = "silence-timeout", help = "Timeout (in seconds) since the last log output of the running WASM process")]
    silence_timeout: Option<u32>,

    #[arg(
        long = "launch-debug-port",
        default_value = "9222",
        help = "Port to use for debugging the launched browser."
    )]
    launch_debug_port: u16,

    #[arg(long = "wait-after-error", default_value = "3", help = "How long to wait after first error is received.")]
    wait_after_error: u32,

    #[arg(long = "chrome-logging", help = "Enable logging from Chrome")]
    chrome_logging: bool,

    #[arg(long = "chrome-log-path", help = "Directory to write Chrome logs to")]
    chrome_log_path: Option<String>,

    #[arg(
        long = "allowed-chrome-crashes",
        default_value = "3",
        help = "Number of Chrome crashes to allow before exiting"
    )]
    allowed_chrome_crashes: u32,

    #[arg(help = "Arguments to pass to Chrome")]
    url_args: Option<Vec<String>>,

    #[arg(long = "hostname", default_value = "localhost", help = "Hostname to use for serving")]
    hostname: String,

    #[arg(long = "strict-port", help = "Only use assigned ports and do not try to find a free one.")]
    strict_port: bool,

    #[arg(long = "pageload-timeout", default_value = "20", help = "Timeout for page load. Only used when --launch-chrome is enabled.")]
    pageload_timeout: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum BuildType {
    Raw,
    Release,
    DevRelease,
    Debug,
}

fn dir_from_build_type(&build_type: &BuildType) -> Option<&'static str> {
    match build_type {
        BuildType::Raw        => None,
        BuildType::Release    => Some("Release"   ),
        BuildType::DevRelease => Some("DevRelease"),
        BuildType::Debug      => Some("Debug"     ),
    }
}


pub struct ValidatedOpts {
    pub build_type:             BuildType,
    pub root_path:              PathBuf,
    pub full_serve_path:        PathBuf,
    pub port:                   u16,
    pub cross_origin:           bool,
    pub launch_chrome:          bool,
    pub lauch_timeout:          Option<u32>,
    pub pageload_timeout:       u32,
    pub silence_timeout:        Option<u32>,
    pub launch_debug_port:      u16,
    pub wait_after_error:       u32,
    pub full_url_arg:           Option<String>,
    pub full_chrome_path:       String,
    pub chrome_log_path:        String,
    pub chrome_logging_prefix:  String,
    pub allowed_chrome_crashes: u32,
    pub chrome_logging:         bool,
    pub hostname:               String,
    pub strict_port:            bool,
}

fn validate_opts(opts: Opts) -> ValidatedOpts {
    let build_type = match (opts.use_release, opts.use_dev_release, opts.use_debug) {
        (false, false, false) => BuildType::Raw, // Default to raw
        (true, false, false) => BuildType::Release,
        (false, true, false) => BuildType::DevRelease,
        (false, false, true) => BuildType::Debug,
        _ => panic!(
            "Invalid build type specified. Release: {}, DevRelease: {}, Debug: {}",
            opts.use_release, opts.use_dev_release, opts.use_debug
        ),
    };

    let root_prefix = dir_from_build_type(&build_type);

    let root_path = match opts.input {
        Some(path) => path,
        None => std::env::current_dir().unwrap(),
    };

    let full_serve_path = match root_prefix {
        Some(prefix) => root_path.join(prefix),
        None => root_path.clone(),
    };

    let mut full_url_arg = None;

    if let Some(mut url_args) = opts.url_args {

        if let Some(ref mut first_element) = url_args.first_mut() {
            // If the user forgot to add .html to the URL, we'll add it for them
            if !first_element.ends_with(".html") {
                first_element.push_str(".html")
            }

            // Check immediately if the first argument is an existing file
            let full_path = full_serve_path.join(first_element);
            if !full_path.exists() {
                print_red(&format!("FILE NOT FOUND: {}", full_path.to_string_lossy()));
                panic!();
            }
        }

        let mut url_args = url_args.into_iter().peekable();

        if let Some(url) = url_args.next() {
            let mut full_url = url;

            let possible_prefix = format!("http://{}:{}/", &opts.hostname, opts.port);

            if full_url.starts_with(&possible_prefix) {
                print_yellow(&format!("No need to http://{}:{}/ prefix", &opts.hostname, opts.port));
                full_url = full_url.replacen(&possible_prefix, "", 1);
            }

            if url_args.peek().is_some() {
                full_url.push('?');
                while let Some(arg) = url_args.next() {
                    full_url.push_str(&arg);
                    if url_args.peek().is_some() {
                        full_url.push('&');
                    }
                }
            }

            full_url_arg = Some(full_url);
        }
    }

    if opts.launch_chrome && full_url_arg.is_none() {
        print_red("NO URL ARGUMENT FOR --launch-chrome");
        panic!();
    }

    let full_chrome_path = match opts.chrome_path {
        Some(path) => path,
        None => {
            match env::var("POSLUZNIK_CHROME_PATH") {
                Ok(val) => val,
                Err(_) => {
                    // TODO: Fix for other platforms
                    #[cfg(target_os = "macos")]
                    let chrome_path = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

                    #[cfg(target_os = "linux")]
                    let chrome_path = "/usr/bin/google-chrome";

                    chrome_path.to_string()
                }
            }
        }
    };

    let chrome_logging = match opts.chrome_logging {
        true => true,
        false => match env::var("POSLUZNIK_CHROME_LOGGING") {
            Ok(val) => match val.as_str() {
                "1" | "true"  | "True"  | "TRUE"  => true,
                "0" | "false" | "False" | "FALSE" => false,
                _ => {
                    panic!("Invalid value for POSLUZNIK_CHROME_LOGGING: {}", val);
                }
            },
            Err(_) => false,
        },
    };

    let chrome_log_path = match opts.chrome_log_path {
        Some(path) => path,
        None => match env::var("POSLUZNIK_CHROME_LOG_PATH") {
            Ok(val) => val,
            Err(_) => root_path.to_string_lossy().to_string(),
        },
    };

    let chrome_logging_prefix = uuid::Uuid::new_v4().to_string();

    ValidatedOpts {
        build_type,
        port: opts.port,
        root_path,
        full_serve_path: full_serve_path.to_path_buf(),
        cross_origin: opts.cross_origin,
        launch_chrome: opts.launch_chrome,
        lauch_timeout: opts.lauch_timeout,
        pageload_timeout: opts.pageload_timeout,
        silence_timeout: opts.silence_timeout,
        launch_debug_port: opts.launch_debug_port,
        wait_after_error: opts.wait_after_error,
        full_url_arg,
        chrome_log_path,
        full_chrome_path,
        chrome_logging_prefix,
        allowed_chrome_crashes: opts.allowed_chrome_crashes,
        chrome_logging,
        hostname: opts.hostname,
        strict_port: opts.strict_port,
    }
}

pub fn get_opts() -> ValidatedOpts {
    validate_opts(Opts::parse())
}
