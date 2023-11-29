mod chrome_control;
mod chrome_debug_api_response;
mod configuration;
mod printer;

use std::{net::SocketAddr, path::PathBuf};

use axum::{
    body::{Bytes, Full},
    extract::{Path, State},
    http::{response::Builder, Response, StatusCode},
    routing::{get, post},
    Router,
};

use printer::{print_blue, print_red};

use crate::{
    chrome_control::{ChromeDebuggerEvent, ChromeUnderControl, ConsoleCallType},
    printer::print_yellow,
};

async fn post_stdio(State(app_state): State<AppState>, request: Bytes) {
    if request.starts_with(b"^out^") {
        if app_state.stdio_logging {
            let parts = request.split(|b| *b == b'^').collect::<Vec<_>>();
            if parts.len() < 4 {
                print_yellow(&format!("INVALID STDIO.HTML REQUEST: {:?}", request));
                return;
            }

            let out = percent_encoding::percent_decode(parts[3]).decode_utf8_lossy();

            println!("{}", out);
        }
    } else if request.starts_with(b"^err^") {
        if app_state.stdio_logging {
            let parts = request.split(|b| *b == b'^').collect::<Vec<_>>();
            if parts.len() < 4 {
                print_yellow(&format!("INVALID STDIO.HTML REQUEST: {:?}", request));
                return;
            }

            let err = percent_encoding::percent_decode(parts[3]).decode_utf8_lossy();

            print_red(&err);
        }
    } else if request.starts_with(b"^exit^") {
        print_blue("EXIT RECEIVED");
        if app_state.launch_chrome {
            let _ = app_state.shutdown_tx.send(ShutdownEvent::ExitRequest).await;
        }
    } else {
        print_blue(&format!("GOT STDIO.HTML REQUEST: {:?}", request));
    }
}

fn dir_from_build_type(&build_type: &configuration::BuildType) -> Option<&'static str> {
    match build_type {
        configuration::BuildType::Raw => None,
        configuration::BuildType::Release => Some("Release"),
        configuration::BuildType::DevRelease => Some("DevRelease"),
        configuration::BuildType::Debug => Some("Debug"),
    }
}

async fn general_serve(Path(p): Path<String>, State(app_state): State<AppState>) -> Response<Full<Bytes>> {
    print_blue(&format!("GET_REQUEST: {}", p));

    let prefix = dir_from_build_type(&app_state.build_type);

    // determine the directory to serve from
    let dir = match prefix {
        Some(prefix) => std::path::Path::join(&app_state.serve_root, prefix),
        None => app_state.serve_root.clone(),
    };

    let file_candidate = std::path::Path::join(&dir, &p);

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
    pub serve_root:    PathBuf,
    pub build_type:    configuration::BuildType,
    pub cross_origin:  bool,
    pub launch_chrome: bool,
    pub shutdown_tx:   tokio::sync::mpsc::Sender<ShutdownEvent>,
    pub stdio_logging: bool,
}

fn print_all_html_file_links_for_user_comfort(args: &configuration::ValidatedOpts) {
    // determine the directory to serve from
    let prefix = dir_from_build_type(&args.build_type);

    let full_serve_path = match prefix {
        Some(prefix) => std::path::Path::join(&args.root_path, prefix),
        None => args.root_path.clone(),
    };

    println!("Serving from : {}", full_serve_path.to_string_lossy());
    println!("  Build type : {:?}", args.build_type);
    println!("Cross origin : {:?}", args.cross_origin);
    println!();

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

    for entry in std::fs::read_dir(&full_serve_path).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.is_file() {
            let path = path.strip_prefix(&full_serve_path).unwrap();
            let path = path.to_str().unwrap_or_default();

            if path.ends_with(".html") {
                println!("http://localhost:{}/{}", args.port, path);
            }
        }
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), ()> {
    let args = configuration::get_opts();

    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).init();

    print_all_html_file_links_for_user_comfort(&args);

    for run_attempt_index in 0..(args.allowed_chrome_crashes + 1u32) {
        match single_run_main(&args).await {
            Ok(ShutdownEvent::ExitRequest) => {
                print_blue("SUCCESS");
                return Ok(());
            }
            Ok(ShutdownEvent::ChromeCrash) => {
                print_red("CHROME INTERNAL CRASH");
                if run_attempt_index + 1 < args.allowed_chrome_crashes {
                    print_blue(&format!("RESTARTING CHROME (ATTEMPT {})", run_attempt_index + 2));
                }
            }
            Ok(ShutdownEvent::TestFailure) => {
                print_red("TEST FAILURE");
                return Err(());
            }
            Ok(ShutdownEvent::LaunchTimeout) => {
                print_yellow("LAUNCH TIMEOUT");
                return Err(());
            }
            Ok(ShutdownEvent::UserCancel) => {
                print_yellow("USER CANCEL");
                return Err(());
            }
            Err(()) => {
                print_red("MEASUREMENT FAILURE");
                return Err(());
            }
        }
    }

    print_yellow("TOO MANY CHROME CRASHES");
    Err(())
}

#[derive(Copy, Clone, Debug)]
enum ShutdownEvent {
    ExitRequest,
    UserCancel,
    ChromeCrash,
    TestFailure,
    LaunchTimeout,
}

async fn single_run_main(args: &configuration::ValidatedOpts) -> Result<ShutdownEvent, ()> {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<ShutdownEvent>(8);

    let app_state = AppState {
        serve_root:    args.root_path.clone(),
        build_type:    args.build_type,
        cross_origin:  args.cross_origin,
        launch_chrome: args.launch_chrome,
        shutdown_tx:   shutdown_tx.clone(),
        stdio_logging: !args.launch_chrome,
    };

    let mut chrome: Option<chrome_control::ChromeUnderControl> = None;

    let addr = SocketAddr::from(([127, 0, 0, 1], args.port));

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

        axum::Server::bind(&addr).serve(app).await
    });

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
                async move {
                    match event {
                        ChromeDebuggerEvent::ConsoleAPICalled { msg, message_type } => match message_type {
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
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(launch_timeout as u64)).await;
            print_red("LAUNCH TIMEOUT EXPIRED");

            // Ignore the send error if the channel is closed (which it will be if the server shuts down)
            let _ = shutdown_tx.send(ShutdownEvent::LaunchTimeout).await;
        });
    }

    let shutdown_event = shutdown_task.await;

    print_blue("DROPPING SERVER");
    // Server is aborted in order to free up the port.
    server_task.abort_handle().abort();
    // Wait in oder to give the server time to shut down.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

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
