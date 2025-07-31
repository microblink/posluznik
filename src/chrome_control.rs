use futures_util::{Future, SinkExt, StreamExt};
use serde::Deserialize;
use thiserror::Error;

use crate::printer::{print_blue, print_red, print_yellow};

pub type ChromeError = Box<dyn std::error::Error>;

// Chrome dev tools protocol:
// https://chromedevtools.github.io/devtools-protocol/

#[derive(Deserialize, Debug)]
pub struct ChromeVersion {
    #[serde(rename = "Browser")]
    pub browser: String,

    #[serde(rename = "User-Agent")]
    pub user_agent: String,

    #[serde(rename = "V8-Version")]
    pub v8_version: String,

    #[serde(rename = "WebKit-Version")]
    pub webkit_version: String,

    #[serde(rename = "Protocol-Version")]
    pub protocol_version: String,

    #[serde(rename = "webSocketDebuggerUrl")]
    pub web_socket_debugger_url: String,
}

#[derive(Deserialize, Debug)]
pub struct PageInfo {
    pub id: String,

    pub title:     String,
    #[serde(rename = "type")]
    pub page_type: String,

    pub url: String,

    #[serde(rename = "webSocketDebuggerUrl")]
    pub web_socket_debugger_url: String,
}

pub async fn is_running_at(port: u16) -> bool {
    // Ping the port to see if it's running
    // If it's running, we'll get a response
    // If it's not running, we'll get an error
    let url = format!("http://localhost:{port}/json/version");
    let resp = reqwest::get(url).await;
    resp.is_ok()
}

pub async fn get_chrome_version(port: u16) -> Result<ChromeVersion, ChromeError> {
    let url = format!("http://localhost:{port}/json/version");
    let resp = reqwest::get(url).await?;
    let chrome_version = resp.json::<ChromeVersion>().await?;
    Ok(chrome_version)
}

pub async fn get_pages(port: u16) -> Result<Vec<PageInfo>, ChromeError> {
    let url = format!("http://localhost:{port}/json/list");
    let resp = reqwest::get(url).await?;
    let pages = resp.json::<Vec<PageInfo>>().await?;
    Ok(pages)
}

pub struct ChromeUnderControl {
    port:          u16,
    proc_handle:   tokio::process::Child,
    stream_sender: tokio::sync::mpsc::Sender<tokio_tungstenite::tungstenite::Message>,
    id_counter:    IdCounter,
}

#[derive(Debug, Error)]
pub enum ChromeLaunchError {
    #[error("Chrome is already running at port {debug_port}")]
    ChromeAlreadyRunningError { debug_port: u16 },

    #[error("Error launching chrome: {0}")]
    ChromeProcessLaunchError(#[from] std::io::Error),

    #[error("Error getting chrome version: {err}")]
    ChromeVersionError { err: ChromeError },

    #[error("Error getting chrome pages: {err}")]
    ChromeGetPagesError { err: ChromeError },

    #[error("Invalid page count at launch. Expected 1, got {page_count}")]
    InvalidNumberOfPagesAtLaunch { page_count: usize },

    #[error("Error during chrome setup")]
    ErrorDuringChromeSetup,
}

pub enum ConsoleCallType {
    Log,
    Error,
    Warning,
    Info,
    Debug,
    Other,
}

pub enum ChromeDebuggerEvent {
    ConsoleAPICalled { msg: String, message_type: ConsoleCallType },
    ExceptionThrown(String),
    ChromeDebuggerCrashed(String),
    OtherTextMessage(String),
    NonTextMessage(Vec<u8>),
    DebuggerResult(String),
    DebuggerParsingError(String, serde_json::Error),
    DebuggerSocketError(tokio_tungstenite::tungstenite::Error),
    DebuggerAttached{
        target_id:            String,
        session_id:           String,
        target_type:          String,
        waiting_for_debugger: bool,
    },
}

#[derive(Debug, Clone)]
struct IdCounter(std::sync::Arc<std::sync::atomic::AtomicI64>);

impl IdCounter {
    pub fn new() -> Self {
        Self(std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0)))
    }

    pub fn next(&self) -> i64 {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }
}

// event handler must be async
impl ChromeUnderControl {
    pub async fn launch<F, T>(
        chrome_path: &str,
        chrome_log_path: &str,
        logging_prefix: &str,
        port: u16,
        debug_port: u16,
        chrome_logging: bool,
        event_handler: F,
    ) -> Result<Self, ChromeLaunchError>
    where
        F: FnMut(ChromeDebuggerEvent) -> T + Send + Sync + 'static,
        T: Future<Output = ()> + Send + 'static,
    {
        // Check if chrome is already running at the debug port.
        // If it is, we don't want to launch another instance
        if is_running_at(debug_port).await {
            return Err(ChromeLaunchError::ChromeAlreadyRunningError { debug_port });
        }

        let about_blank_url = format!("http://localhost:{}/about:blank", port);

        // Construct the command to launch chrome
        let mut cmd = Self::constuct_launch_command(chrome_path, chrome_log_path, logging_prefix, &about_blank_url, debug_port, chrome_logging);

        let mut proc_handle = cmd.spawn().map_err(ChromeLaunchError::ChromeProcessLaunchError)?;

        // Wait for chrome to start so that users can immediately start using it
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // Check again if the process is still running
        match proc_handle.try_wait() {
            Ok(Some(status)) => {
                print_red(&format!("Chrome process exited with status: {:?}", status));
                return Err(ChromeLaunchError::ErrorDuringChromeSetup);
            }
            Ok(None) => {
                print_blue("Chrome process is running");
            }
            Err(e) => {
                print_red(&format!("Error checking if chrome process is running: {}", e));
                return Err(ChromeLaunchError::ErrorDuringChromeSetup);
            }
        }

        // Get the chrome version info... allow for some retries
        let mut chrome_version_info: Option<ChromeVersion> = None;

        // Retry getting chrome version 5 times
        for attempt_index in 0..5 {
            match get_chrome_version(debug_port).await {
                Ok(version) => {
                    chrome_version_info = Some(version);
                    break;
                }
                Err(e) => {
                    print_yellow(&format!("Error getting chrome version: {}", e));
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    if attempt_index == 4 {
                        return Err(ChromeLaunchError::ChromeVersionError { err: e });
                    }
                }
            }
        }
        let chrome_version_info = chrome_version_info.unwrap();

        print_blue(&format!("CHROME INFO:\n{:?}", chrome_version_info.browser));

        // Get all pages. Expect only one page (the blank one)
        let pages = get_pages(debug_port)
            .await
            .map_err(|e| ChromeLaunchError::ChromeGetPagesError { err: e })?;

        print_blue(&format!("PAGES:\n{:?}", pages));

        // Find the "about:blank" page
        let pages = pages.into_iter().filter(|page| page.url == about_blank_url).collect::<Vec<_>>();

        // Checkt that there is 1 about:blank page
        if pages.len() != 1 {
            print_red(&format!("Invalid number of pages: {}", pages.len()));
            return Err(ChromeLaunchError::ErrorDuringChromeSetup);
        }

        // Connect to the chrome debugger at that page
        let stream = match tokio_tungstenite::connect_async(&pages[0].web_socket_debugger_url).await {
            Ok((stream, response)) => {
                print_blue(&format!("CONNECTED TO CHROME DEBUGGER:\n{:?}", response));
                stream
            }
            Err(e) => {
                print_red(&format!("Error connecting to chrome debugger: {}", e));
                return Err(ChromeLaunchError::ErrorDuringChromeSetup);
            }
        };

        // Create the sender and receiver for the websocket
        let (mut sender, mut receiver) = stream.split();

        // Create a channel for sending events. This needs to be done because some events need to be sent from other tasks.
        let (event_sender_tx, mut event_sender_rx) = tokio::sync::mpsc::channel::<tokio_tungstenite::tungstenite::Message>(16);

        // Create a task which just sends events to the websocket
        tokio::spawn(async move {
            while let Some(event) = event_sender_rx.recv().await {
                match sender.send(event).await {
                    Ok(_) => {
                        print_blue("Event sent to websocket");
                    }
                    Err(e) => {
                        print_red(&format!("Error sending event to websocket: {}", e));
                    }

                }
            }
        });

        let id_counter = IdCounter::new();

        // Enable runtime logging
        let enable_runtime_message = format!("{{\"id\":{},\"method\":\"Runtime.enable\"}}", id_counter.next());
        print_blue(&format!("Sending enable runtime message: {}", enable_runtime_message));
        event_sender_tx
            .send(tokio_tungstenite::tungstenite::Message::Text(enable_runtime_message))
            .await
            .map_err(|_| ChromeLaunchError::ErrorDuringChromeSetup)?;

        // Enable debugger
        let enable_debugger_message = format!("{{\"id\":{},\"method\":\"Debugger.enable\"}}", id_counter.next());
        print_blue(&format!("Sending enable debugger message: {}", enable_debugger_message));
        event_sender_tx
            .send(tokio_tungstenite::tungstenite::Message::Text(enable_debugger_message))
            .await
            .map_err(|_| ChromeLaunchError::ErrorDuringChromeSetup)?;

        // Enable inspector
        let enable_inspector_message = format!("{{\"id\":{},\"method\":\"Inspector.enable\"}}", id_counter.next());
        print_blue(&format!("Sending enable inspector message: {}", enable_inspector_message));
        event_sender_tx
            .send(tokio_tungstenite::tungstenite::Message::Text(enable_inspector_message))
            .await
            .map_err(|_| ChromeLaunchError::ErrorDuringChromeSetup)?;

        // Set auto attach to true
        let auto_attach_message = format!(
            "{{\"id\":{},\"method\":\"Target.setAutoAttach\",\"params\":{{\"autoAttach\":true,\"waitForDebuggerOnStart\":true,\"flatten\":true}}}}",
            id_counter.next()
        );
        print_blue(&format!("Sending auto attach message: {}", auto_attach_message));
        event_sender_tx
            .send(tokio_tungstenite::tungstenite::Message::Text(auto_attach_message))
            .await
            .map_err(|_| ChromeLaunchError::ErrorDuringChromeSetup)?;

        // Set runIfWaitingForDebugger to true
        let run_if_waiting_for_debugger_message = format!("{{\"id\":{},\"method\":\"Runtime.runIfWaitingForDebugger\"}}", id_counter.next());
        print_blue(&format!("Sending runIfWaitingForDebugger message: {}", run_if_waiting_for_debugger_message));
        event_sender_tx
            .send(tokio_tungstenite::tungstenite::Message::Text(run_if_waiting_for_debugger_message))
            .await
            .map_err(|_| ChromeLaunchError::ErrorDuringChromeSetup)?;

        let event_sender_tx_clone = event_sender_tx.clone();
        let id_counter_clone = id_counter.clone();

        // Create the receiver which will emit deubgger events.
        tokio::spawn(async move {
            let mut f = event_handler;
            while let Some(msg) = receiver.next().await {
                match msg {
                    Ok(msg) => {
                        if msg.is_text() {
                            let text_msg = msg.to_text().unwrap();
                            let api_result = serde_json::from_str::<crate::chrome_debug_api_response::APIResult>(text_msg);
                            if let Ok(api_result) = api_result {
                                f(ChromeDebuggerEvent::DebuggerResult(api_result.result.to_string())).await;
                            } else {
                                let api_response = serde_json::from_str::<crate::chrome_debug_api_response::APIResponse>(text_msg);
                                match api_response {
                                    Ok(response) => match response.method.as_str() {
                                        "Runtime.consoleAPICalled" => {
                                            let console_api_response =
                                                serde_json::from_value::<crate::chrome_debug_api_response::ConsoleAPICalledResponse>(response.params);
                                            match console_api_response {
                                                Ok(console_api_response) => {
                                                    let msg = console_api_response.get_log_message();
                                                    let message_type = match console_api_response.console_call_type.as_str() {
                                                        "log" => ConsoleCallType::Log,
                                                        "error" => ConsoleCallType::Error,
                                                        "warning" => ConsoleCallType::Warning,
                                                        "info" => ConsoleCallType::Info,
                                                        "debug" => ConsoleCallType::Debug,
                                                        _ => ConsoleCallType::Other,
                                                    };
                                                    f(ChromeDebuggerEvent::ConsoleAPICalled { msg, message_type }).await;
                                                }
                                                Err(e) => {
                                                    f(ChromeDebuggerEvent::DebuggerParsingError(text_msg.to_owned(), e)).await;
                                                }
                                            }
                                        }
                                        "Runtime.exceptionThrown" => {
                                            f(ChromeDebuggerEvent::ExceptionThrown(text_msg.to_owned())).await;
                                        }
                                        "Inspector.targetCrashed" => {
                                            f(ChromeDebuggerEvent::ChromeDebuggerCrashed(text_msg.to_owned())).await;
                                        }
                                        "Target.attachedToTarget" => {
                                             // This message is received when a worker is launched. We need to
                                             // enable the runtime and debugger for the worker as well.

                                            let target_attached_to_target_response =
                                                serde_json::from_value::<crate::chrome_debug_api_response::TargetAttachedToTargetResponse>(response.params);

                                            match target_attached_to_target_response {
                                                Ok(target_attached_to_target_response) => {
                                                    let target_id = target_attached_to_target_response.target_info.target_id;
                                                    let session_id = target_attached_to_target_response.session_id;

                                                    let enable_runtime_message = format!(
                                                        "{{\"id\":{}, \"sessionId\": \"{}\", \"method\":\"Runtime.enable\"}}",
                                                        id_counter_clone.next(),
                                                        session_id
                                                    );
                                                    print_blue(&format!("Sending enable runtime message: {}", enable_runtime_message));
                                                    let _ = event_sender_tx_clone
                                                        .send(tokio_tungstenite::tungstenite::Message::Text(enable_runtime_message))
                                                        .await;

                                                    // Enable debugger
                                                    let enable_debugger_message = format!(
                                                        "{{\"id\":{}, \"sessionId\": \"{}\", \"method\":\"Debugger.enable\"}}",
                                                        id_counter_clone.next(),
                                                        session_id
                                                    );
                                                    print_blue(&format!("Sending enable debugger message: {}", enable_debugger_message));
                                                    let _ = event_sender_tx_clone
                                                        .send(tokio_tungstenite::tungstenite::Message::Text(enable_debugger_message))
                                                        .await;

                                                    // Skip sending `Inspector.enable` message because chrome complains with the following message:
                                                    // "'Inspector.enable' wasn't found"
                                                    // This happens only when the `sessionId` is sent. If the `sessionId` is not sent, the message is accepted.
                                                    // but this message is already sent on startup.

                                                    // Now continue running the worker
                                                    let continue_running_message = format!(
                                                        "{{\"id\":{}, \"sessionId\": \"{}\", \"method\":\"Runtime.runIfWaitingForDebugger\"}}",
                                                        id_counter_clone.next(),
                                                        session_id
                                                    );

                                                    let _ = event_sender_tx_clone
                                                        .send(tokio_tungstenite::tungstenite::Message::Text(continue_running_message))
                                                        .await;

                                                    f(ChromeDebuggerEvent::DebuggerAttached {
                                                        target_id,
                                                        session_id,
                                                        target_type: target_attached_to_target_response.target_info.title,
                                                        waiting_for_debugger: target_attached_to_target_response.waiting_for_debugger,
                                                    }).await;
                                                }
                                                Err(e) => {
                                                    f(ChromeDebuggerEvent::DebuggerParsingError(text_msg.to_owned(), e)).await;
                                                }
                                            }
                                        }
                                        _ => {
                                            f(ChromeDebuggerEvent::OtherTextMessage(text_msg.to_owned())).await;
                                        }
                                    },
                                    Err(e) => {
                                        f(ChromeDebuggerEvent::DebuggerParsingError(text_msg.to_owned(), e)).await;
                                    }
                                }
                            }
                        } else {
                            f(ChromeDebuggerEvent::NonTextMessage(msg.into_data())).await;
                        }
                    }
                    Err(e) => {
                        f(ChromeDebuggerEvent::DebuggerSocketError(e)).await;
                    }
                }
            }
        });

        Ok(Self {
            port,
            proc_handle,
            stream_sender: event_sender_tx,
            id_counter
        })
    }

    fn advance_websocket_id(&mut self) -> i64 {
        self.id_counter.next()
    }

    pub async fn navigate_to(&mut self, url: &str) -> Result<(), ChromeError> {
        let url = format!("http://localhost:{}/{}", self.port, url);
        let id = self.advance_websocket_id();

        print_blue(&format!("Navigating to {}", url));

        self.stream_sender
            .send(tokio_tungstenite::tungstenite::Message::Text(format!(
                "{{\"id\":{},\"method\":\"Page.navigate\",\"params\":{{\"url\":\"{}\"}}}}",
                id, url
            )))
            .await?;

        Ok(())
    }

    pub async fn soft_close(self) -> Result<(), ChromeError> {
        // Make myself mutable
        let mut myself = self;

        // First be nice
        unsafe {
            libc::kill(myself.proc_handle.id().unwrap() as i32, libc::SIGTERM);
        };

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        // Then be less nice
        match myself.proc_handle.kill().await {
            Ok(_) => Ok(()),
            Err(e) => Err(Box::new(e)),
        }
    }

    fn constuct_launch_command(
        chrome_path: &str,
        chrome_log_path: &str,
        logging_prefix: &str,
        open_url: &str,
        debug_port: u16,
        chrome_logging: bool,
    ) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(chrome_path);

        cmd.arg("--headless");
        cmd.arg("--disable-gpu");
        cmd.arg("--no-sandbox");
        cmd.arg("--disable-dev-shm-usage");
        cmd.arg(format!("--remote-debugging-port={}", debug_port));
        cmd.arg("--use-gl=swiftshader");
        cmd.arg("--renderer-process-limit=1");
        cmd.arg("--no-zygote");
        cmd.arg("--disable-shared-workers");

        if chrome_logging {
            cmd.arg("--enable-logging");
            cmd.arg("--v=1");

            cmd.env("CHROME_LOG_FILE", format!("{}/chrome-{}.log", chrome_log_path, logging_prefix));
        }

        cmd.arg(open_url);

        cmd
    }
}
