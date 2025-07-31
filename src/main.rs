mod chrome_control;
mod chrome_debug_api_response;
mod configuration;
mod printer;
mod stdio_html_request_parser;

use std::{net::{SocketAddr, IpAddr}, path::PathBuf};

use axum::{
    body::{Bytes, Full},
    extract::{Path, State},
    http::{response::Builder, Response, StatusCode},
    routing::{get, post},
    Router,
};

use printer::{print_blue, print_red};
use stdio_html_request_parser::{parse_request, StdioParsingOptions, StdioRequest, StdioRequestParseError};

use crate::{
    chrome_control::{ChromeDebuggerEvent, ChromeUnderControl, ConsoleCallType},
    printer::print_yellow,
};

async fn post_stdio(State(app_state): State<AppState>, request: Bytes) {

    let parse_options = StdioParsingOptions {
        parse_stdio_output: app_state.stdio_logging,
    };

    match parse_request(&parse_options, &request) {
        Ok(parsed) => match parsed {
            StdioRequest::ConsoleOutput(out) => {
                println!("{}", out);
                let _ = app_state.silence_tx.send(tokio::time::Instant::now()).await;
            }
            StdioRequest::ConsoleError(err) => {
                print_red(&err);
                let _ = app_state.silence_tx.send(tokio::time::Instant::now()).await;
            }
            StdioRequest::IgnoredRequest => {},
            StdioRequest::ExitRequest => {
                print_blue("EXIT RECEIVED");
                if app_state.launch_chrome {
                    let _ = app_state.shutdown_tx.send(ShutdownEvent::ExitRequest).await;
                }
            }
            StdioRequest::PageLoad => {
                print_blue("PAGE LOAD RECEIVED");
                if app_state.launch_chrome {
                    // Only send the page load event if chrome is launched
                    // Otherwise nobody will empty the channel and the server will hang
                    let _ = app_state.pageload_tx.send(()).await;
                }
            }
        }
        Err(err) => match err {
            StdioRequestParseError::UnknownRequest(err) => {
                print_blue(&format!("GOT STDIO.HTML REQUEST: {}", err));
            }
            StdioRequestParseError::InvalidRequest(err) => {
                print_yellow(&format!("INVALID STDIO.HTML REQUEST: {}", err));
            }
        }
    }
}


async fn general_serve(Path(p): Path<String>, State(app_state): State<AppState>) -> Response<Full<Bytes>> {
    print_blue(&format!("GET_REQUEST: {}", p));

    let file_candidate = std::path::Path::join(&app_state.full_serve_path, &p);

    if file_candidate.is_file() {
        print_blue(&format!("FOUND_FILE: {:?}", file_candidate));
        let bytes = Bytes::from(std::fs::read(file_candidate).unwrap());

        let content_length = bytes.len();

        let body = Full::new(bytes);

        let mut content_type = "text/plain";
        if p.ends_with(".html") {
            content_type = "text/html";
        } else if p.ends_with(".js") {
            content_type = "text/javascript";
        } else if p.ends_with(".css") {
            content_type = "text/css";
        } else if p.ends_with(".wasm") {
            content_type = "application/wasm";
        }

        let mut builder = Builder::new()
            .status(StatusCode::OK)
            .header("content-type", content_type)
            .header("content-length", content_length);

        // Add same origin headers by default. If the user has specified --cross-origin, then we don't add these headers.
        if !app_state.cross_origin {
            builder = builder
                .header("cross-origin-opener-policy", "same-origin")
                .header("cross-origin-embedder-policy", "require-corp");
        }

        return builder.body(body).unwrap();
    }

    Builder::new().status(StatusCode::NOT_FOUND).body("NOT FOUND".into()).unwrap()
}

#[derive(Debug, Clone)]
struct AppState {
    pub full_serve_path: PathBuf,
    pub cross_origin:    bool,
    pub launch_chrome:   bool,
    pub shutdown_tx:     tokio::sync::mpsc::Sender<ShutdownEvent>,
    pub stdio_logging:   bool,
    pub pageload_tx:     tokio::sync::mpsc::Sender<()>,
    pub silence_tx:      tokio::sync::mpsc::Sender<tokio::time::Instant>,
}

fn print_all_html_file_links_for_user_comfort(args: &configuration::ValidatedOpts) {
    println!("Serving from : {}"  , args.full_serve_path.display());
    println!("  Build type : {:?}", args.build_type);
    println!("Cross origin : {:?}", args.cross_origin);
    println!("    hostname : {}"  , args.hostname);
    println!("        port : {}"  , args.port);
    println!();

    if let Some(full_url) = &args.full_url_arg {
        println!("Full URL: http://{}:{}/{}", &args.hostname, args.port, full_url);
        println!();
    }

    if args.launch_chrome {
        println!("Chrome will be launched with the following arguments:");
        println!("{}", args.full_url_arg.as_ref().unwrap());
        if args.chrome_logging {
            println!("    Logging to : {}", args.chrome_log_path);
            println!("Logging prefix : {}", args.chrome_logging_prefix);
        }
        println!();
    }

    println!("You can open the following links in your browser:");

    for entry in std::fs::read_dir(&args.full_serve_path).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.is_file() {
            let path = path.strip_prefix(&args.full_serve_path).unwrap();
            let path = path.to_str().unwrap_or_default();

            if path.ends_with(".html") {
                println!("http://{}:{}/{}", &args.hostname, args.port, path);
            }
        }
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), ()> {
    let mut args = configuration::get_opts();

    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).init();

    for run_attempt_index in 0..(args.allowed_chrome_crashes + 1u32) {
        match single_run_main(&args).await {
            Ok(ShutdownEvent::ExitRequest) => {
                print_blue("SUCCESS");
                return Ok(());
            }
            Ok(ShutdownEvent::ChromeCrash) => {
                print_red("CHROME INTERNAL CRASH");
                if run_attempt_index < args.allowed_chrome_crashes {
                    print_blue(&format!("RESTARTING CHROME (ATTEMPT {})", run_attempt_index + 1));
                }
            }
            Ok(ShutdownEvent::TestFailure) => {
                print_red("TEST FAILURE");
                return Err(());
            }
            Ok(ShutdownEvent::ProcessTimeout) => {
                print_yellow("PROCESS TIMEOUT");
                return Err(());
            }
            Ok(ShutdownEvent::SilenceTimeout) => {
                print_yellow("SILENCE TIMEOUT");
                return Err(());
            }
            Ok(ShutdownEvent::UserCancel) => {
                print_yellow("USER CANCEL");
                return Err(());
            }
            Ok(ShutdownEvent::PortInUse) => {
                print_yellow("PORT IN USE");
                if args.strict_port {
                    print_red("STRICT PORT MODE ENABLED: EXITING");
                    return Err(());
                }
                else if run_attempt_index < args.allowed_chrome_crashes {
                    print_blue(&format!("RESTARTING SERVER (ATTEMPT {})", run_attempt_index + 1));
                    args.port = args.port.saturating_sub(rand::random::<u16>() % 16 + 1);
                }
            }
            Ok(ShutdownEvent::DebugPortInUse) => {
                print_yellow("DEBUG PORT IN USE");
                if args.strict_port {
                    print_red("STRICT PORT MODE ENABLED: EXITING");
                    return Err(());
                }
                else if run_attempt_index < args.allowed_chrome_crashes {
                    print_blue(&format!("RESTARTING SERVER (ATTEMPT {})", run_attempt_index + 1));
                    // Also try to change the port in case the original cause of the issue is some other
                    // process interfering with the port.
                    tokio::time::sleep(tokio::time::Duration::from_secs(args.wait_after_error.into())).await;
                    args.launch_debug_port = args.launch_debug_port.saturating_sub(rand::random::<u16>() % 32 + 3);
                }
            }
            Ok(ShutdownEvent::VersionError(e)) => {
                print_yellow(&format!("CHROME VERSION ERROR: {:?}", e));
                if args.strict_port {
                    print_red("STRICT PORT MODE ENABLED: EXITING");
                    return Err(());
                }
                else if run_attempt_index < args.allowed_chrome_crashes {
                    print_blue(&format!("RESTARTING CHROME (ATTEMPT {})", run_attempt_index + 1));
                    // Also try to change the port in case the original cause of the issue is some other
                    // process interfering with the port.
                    tokio::time::sleep(tokio::time::Duration::from_secs(args.wait_after_error.into())).await;
                    args.launch_debug_port = args.launch_debug_port.saturating_sub(rand::random::<u16>() % 32 + 3);
                }
            }
            Ok(ShutdownEvent::PageLoadTimeout) => {
                print_yellow("PAGE LOAD TIMEOUT");
                if run_attempt_index < args.allowed_chrome_crashes {
                    print_blue(&format!("RESTARTING CHROME (ATTEMPT {})", run_attempt_index + 1));
                    if !args.strict_port {
                        // Also try to change the port in case the original cause of the issue is some other
                        // process interfering with the port.
                        args.port = args.port.saturating_sub(rand::random::<u16>() % 32 + 1);
                        args.launch_debug_port = args.launch_debug_port.saturating_sub(rand::random::<u16>() % 32 + 1);
                    }
                    tokio::time::sleep(tokio::time::Duration::from_secs(args.wait_after_error.into())).await;
                }
            }
            Err(()) => {
                print_red("UNRECOVERABLE SINGLE RUN FAILURE");
                return Err(());
            }
        }
    }

    print_red("TOO MANY CHROME CRASHES");
    Err(())
}

async fn http_server_soft_close<T>(handle: & tokio::task::JoinHandle<Result<(), T>>) {
    // Stop the server
    handle.abort();

    // Wait in order to give the server time to shut down.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
}

#[derive(Clone, Debug)]
enum ShutdownEvent {
    ExitRequest,
    UserCancel,
    ChromeCrash,
    TestFailure,
    ProcessTimeout,
    SilenceTimeout,
    PageLoadTimeout,
    PortInUse,
    DebugPortInUse,
    VersionError(String),
}

async fn single_run_main(args: &configuration::ValidatedOpts) -> Result<ShutdownEvent, ()> {
    print_all_html_file_links_for_user_comfort(args);

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<ShutdownEvent>(8);
    let (silence_tx , mut silence_rx ) = tokio::sync::mpsc::channel::<tokio::time::Instant>(32);
    let (pageload_tx, mut pageload_rx) = tokio::sync::mpsc::channel::<()>(8);

    let app_state = AppState {
        full_serve_path: args.full_serve_path.clone(),
        cross_origin:    args.cross_origin,
        launch_chrome:   args.launch_chrome,
        shutdown_tx:     shutdown_tx.clone(),
        stdio_logging:   !args.launch_chrome,
        pageload_tx:     pageload_tx.clone(),
        silence_tx:      silence_tx.clone(),
    };

    let mut chrome: Option<chrome_control::ChromeUnderControl> = None;

    let ip_addr = match &args.hostname[..] {
        "localhost" => IpAddr::from([127, 0, 0, 1]),
        others => {
            match others.parse::<std::net::IpAddr>() {
                Ok(ip) => ip,
                Err(e) => {
                    print_red(&format!("Invalid hostname: {:?}\n{:?}", args.hostname, e));
                    return Err(());
                }
            }
        }
    };

    let addr = SocketAddr::from((ip_addr, args.port));

    let server_task = tokio::spawn(async move {
        let app = Router::new()
            .route(
                "/",
                get(|| async {
                    print_blue("REQUEST_ROOT");
                    "ROOT"
                }),
            )
            .route("/*p", get(general_serve))
            .route("/stdio.html", get(|| async { "stdio.html should be used as a post requrest target" }))
            .route("/stdio.html", post(post_stdio))
            .with_state(app_state)
            .into_make_service();

        axum::Server::try_bind(&addr)?
            .serve(app)
            .await
    });

    // Wait in order to give the server time to start.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    if server_task.is_finished() {
        print_red("SERVER FAILED TO START");
        match server_task.await {
            Ok(Ok(_)) => {
                print_red("SERVER TASK FAILD SUCCESSFULLY ?!");
                return Err(());
            },
            Ok(Err(e)) => {
                print_red(&format!("SERVER ERROR: {:?}", e));
                return Ok(ShutdownEvent::PortInUse);
            },
            Err(e) => {
                print_red(&format!("SERVER TASK ERROR: {:?}", e));
                return Err(());
            }
        }
    }

    if args.launch_chrome {
        // Only monitor pageloads when chrome is launched

        let pageload_shutdnow_tx = shutdown_tx.clone();
        let pageload_duration = args.pageload_timeout;
        tokio::spawn(async move {
            tokio::select! {
                _ = pageload_rx.recv() => {
                    print_blue("PAGE LOAD RX RECEIVED");
                },
                _ = tokio::time::sleep(std::time::Duration::from_secs(pageload_duration as u64)) => {
                    print_red("PAGE LOAD TIMEOUT EXPIRED");
                    let _ = pageload_shutdnow_tx.send(ShutdownEvent::PageLoadTimeout).await;
                }
            }
            // Keep clearing the channel while the task is running.
            // This might be necessary because someone might be manually opening
            // the page in the browser and we don't want to fill up the channel.
            while (pageload_rx.recv().await).is_some() {}
        });
    }

    let shutdown_task = tokio::spawn(async move {
        let event = shutdown_rx.recv().await;
        print_blue("SHUTDOWN RECEIVED");
        // Last wait
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        event
    });

    if args.launch_chrome {
        let shutdown_from_event_handler = shutdown_tx.clone();
        let launch_fut = ChromeUnderControl::launch(
            &args.full_chrome_path,
            &args.chrome_log_path,
            &args.chrome_logging_prefix,
            args.port,
            args.launch_debug_port,
            args.chrome_logging,
            move |event| {
                let sender = shutdown_from_event_handler.clone();
                let silence_tx = silence_tx.clone();
                async move {
                    match event {
                        ChromeDebuggerEvent::ConsoleAPICalled { msg, message_type } => {
                            match message_type {
                                ConsoleCallType::Error => {
                                    print_red(&msg);
                                }
                                ConsoleCallType::Warning => {
                                    print_yellow(&msg);
                                }
                                ConsoleCallType::Info | ConsoleCallType::Debug | ConsoleCallType::Other => {
                                    print_blue(&msg);
                                }
                                ConsoleCallType::Log => {
                                    println!("{}", msg);
                                }
                            }
                            let _ = silence_tx.send(tokio::time::Instant::now()).await;
                        },
                        ChromeDebuggerEvent::ExceptionThrown(msg) => {
                            print_red(&format!("EXCEPTION THROWN:\n{}", msg));
                            let _ = sender.send(ShutdownEvent::TestFailure).await;
                        }
                        ChromeDebuggerEvent::ChromeDebuggerCrashed(_) => {
                            print_red("CHROME DEBUGGER CRASHED");
                            let _ = sender.send(ShutdownEvent::ChromeCrash).await;
                        }
                        ChromeDebuggerEvent::OtherTextMessage(msg) => {
                            print_blue(&format!("OTHER TEXT MESSAGE: {}", msg));
                        }
                        ChromeDebuggerEvent::NonTextMessage(msg) => {
                            print_blue(&format!("NON TEXT MESSAGE: {:?}", msg));
                        }
                        ChromeDebuggerEvent::DebuggerResult(result) => {
                            print_blue(&format!("DEBUGGER RESULT: {:?}", result));
                        }
                        ChromeDebuggerEvent::DebuggerParsingError(msg, e) => {
                            print_red(&format!("DEBUGGER PARSING ERROR:\n{}\nERR: {:?}", msg, e));
                        }
                        ChromeDebuggerEvent::DebuggerSocketError(e) => {
                            print_red(&format!("DEBUGGER SOCKET ERROR: {:?}", e));
                        }
                        ChromeDebuggerEvent::DebuggerAttached { target_id, session_id, target_type, waiting_for_debugger } => {
                            print_blue("DEBUGGER ATTACHED:");
                            print_blue(&format!("    TARGET_ID : {}", target_id));
                            print_blue(&format!("   SESSION_ID : {}", session_id));
                            print_blue(&format!("  TARGET_TYPE : {}", target_type));
                            print_blue(&format!("      WAITING : {}", waiting_for_debugger));
                        }
                    }
                }
            },
        );

        match launch_fut.await {
            Ok(c) => {
                print_blue("CHROME LAUNCHED");
                chrome = Some(c);
                let ctrl_c_shutdown = shutdown_tx.clone();
                tokio::spawn(async move {
                    if let Ok(()) = tokio::signal::ctrl_c().await {
                        print_blue("CTRL-C RECEIVED");
                        let _ = ctrl_c_shutdown.send(ShutdownEvent::UserCancel).await;
                    }
                });
            }
            Err(e) => {
                print_red(&format!("CHROME LAUNCH ERROR: {:?}", e));

                // Early https server abort to free up the port
                http_server_soft_close(&server_task).await;

                // Return the error. The top level function will decidet what to do with it.
                match e {
                    chrome_control::ChromeLaunchError::ChromeAlreadyRunningError { debug_port: _ } => {
                        return Ok(ShutdownEvent::DebugPortInUse);
                    },
                    chrome_control::ChromeLaunchError::ChromeVersionError { err } => {
                        // A chrome launch error is also related to a debug port in use by another chrome instance.
                        // Returning an `Ok(_)` value in order to trigger another chrome launch attempt.
                        return Ok(ShutdownEvent::VersionError(err.to_string()));
                    },
                    _ => {
                        return Err(());
                    }
                }
            }
        }

        if let Some(chrome) = &mut chrome {
            match chrome.navigate_to(&args.full_url_arg.clone().unwrap()).await {
                Ok(_) => {
                    print_blue("NAVIGATED TO URL");
                }
                Err(e) => {
                    print_red(&format!("NAVIGATE TO URL ERROR: {:?}", e));
                }
            }
        }
    }

    if let Some(launch_timeout) = args.lauch_timeout {
        let shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(launch_timeout as u64)).await;
            print_red("PROCESS TIMEOUT EXPIRED");

            // Ignore the send error if the channel is closed (which it will be if the server shuts down)
            let _ = shutdown_tx.send(ShutdownEvent::ProcessTimeout).await;
        });
    }

    if let Some(silence_timeout) = args.silence_timeout {
        tokio::spawn(async move {
            let mut last_non_silence = tokio::time::Instant::now();
            loop {
                tokio::select! {
                    silence_broken = silence_rx.recv() => {
                        if let Some( t ) = silence_broken {
                            last_non_silence = t;
                        } else {
                            break;
                        }
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                        // check if silence timeout is reached
                        let current_time = tokio::time::Instant::now();
                        let silence_time = current_time - last_non_silence;
                        if silence_time > tokio::time::Duration::from_secs(silence_timeout as u64) {
                            print_red("SILENCE TIMEOUT REACHED");

                            // Ignore the send error if the channel is closed (which it will be if the server shuts down)
                            let _ = shutdown_tx.send(ShutdownEvent::SilenceTimeout).await;

                            // break the infinite loop and finish the task
                            break;
                        }
                    }
                }
            }
        });
    } else {
        drop(silence_rx);
    }

    let shutdown_event = shutdown_task.await;

    print_blue("DROPPING SERVER");

    http_server_soft_close(&server_task).await;

    print_blue("SHUTTING DOWN SERVER");

    if let Some(chrome) = chrome {
        match chrome.soft_close().await {
            Ok(_) => {
                print_blue("CHROME CLOSED");
            }
            Err(e) => {
                print_red(&format!("CHROME CLOSE ERROR: {:?}", e));
                return Err(());
            }
        }
    }

    match shutdown_event {
        Ok(Some(e)) => Ok(e),
        Ok(None) => {
            print_yellow("SHUTDOWN EVENT CHANNEL CLOSED FOR UNKNOWN REASON");
            Err(())
        }
        Err(_) => {
            print_yellow("SHUTDOWN EVENT CHANNEL ERROR");
            Err(())
        }
    }
}
