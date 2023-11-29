use futures_util::{stream::SplitSink, Future, SinkExt, StreamExt};
use serde::Deserialize;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};

use crate::printer::print_blue;

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
    stream_sender: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,

    websocket_id: u32,
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

    #[error("Invalid start page url: {url}")]
    InvalidStartPageUrl { url: String },

    #[error("Error connecting to the debugger: {err}")]
    ErrorConnectingToTheDebugger { err: tokio_tungstenite::tungstenite::Error },

    #[error("Error installing rungime inspector: {err}")]
    ErrorInstalingRuntimeInspector { err: tokio_tungstenite::tungstenite::Error },
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

        let proc_handle = cmd.spawn().map_err(ChromeLaunchError::ChromeProcessLaunchError)?;

        // Wait for chrome to start so that users can immediately start using it
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // Get all chrome information
        let chrome_version_info = get_chrome_version(debug_port)
            .await
            .map_err(|e| ChromeLaunchError::ChromeVersionError { err: e })?;

        print_blue(&format!("CHROME INFO:\n{:?}", chrome_version_info.browser));

        // Get all pages. Expect only one page (the blank one)
        let pages = get_pages(debug_port)
            .await
            .map_err(|e| ChromeLaunchError::ChromeGetPagesError { err: e })?;

        print_blue(&format!("PAGES:\n{:?}", pages));

        if pages.len() != 1 {
            return Err(ChromeLaunchError::InvalidNumberOfPagesAtLaunch { page_count: pages.len() });
        }

        // Check that the page is the blank page
        if pages[0].url != about_blank_url {
            return Err(ChromeLaunchError::InvalidStartPageUrl {
                url: pages[0].url.to_owned(),
            });
        }

        // Connect to the chrome debugger at that page
        let stream = match tokio_tungstenite::connect_async(&pages[0].web_socket_debugger_url).await {
            Ok((stream, response)) => {
                print_blue(&format!("CONNECTED TO CHROME DEBUGGER:\n{:?}", response));
                stream
            }
            Err(e) => {
                return Err(ChromeLaunchError::ErrorConnectingToTheDebugger { err: e });
            }
        };

        let (mut sender, mut receiver) = stream.split();

        // Spawn a task to see mesages which are received from Chrome
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

        // Enable runtime logging
        let enable_runtime_message = "{\"id\":1,\"method\":\"Runtime.enable\"}";
        print_blue(&format!("Sending enable runtime message: {}", enable_runtime_message));
        sender
            .send(tokio_tungstenite::tungstenite::Message::Text(enable_runtime_message.into()))
            .await
            .map_err(|e| ChromeLaunchError::ErrorInstalingRuntimeInspector { err: e })?;

        let enable_inspector_message = "{\"id\":2,\"method\":\"Inspector.enable\"}";
        print_blue(&format!("Sending enable inspector message: {}", enable_inspector_message));
        sender
            .send(tokio_tungstenite::tungstenite::Message::Text(enable_inspector_message.into()))
            .await
            .map_err(|e| ChromeLaunchError::ErrorInstalingRuntimeInspector { err: e })?;

        Ok(Self {
            port,
            proc_handle,
            stream_sender: sender,
            websocket_id: 3, // 1 and 2 are used for navigation and inspection
        })
    }

    fn advance_websocket_id(&mut self) -> u32 {
        self.websocket_id += 1;
        self.websocket_id
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
        cmd.arg("--single-process");
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
