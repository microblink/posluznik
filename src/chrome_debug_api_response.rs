use serde::Deserialize;

// Chrome dev tools protocol:
// https://chromedevtools.github.io/devtools-protocol/

#[derive(Deserialize, Debug)]
pub struct APIResult {
    pub id:     u32,
    pub result: serde_json::Value,
}

#[derive(Deserialize, Debug)]
pub struct APIResponse {
    pub method: String,
    pub params: serde_json::Value,
}

#[derive(Deserialize, Debug)]
pub struct ConsoleAPICalledResponse {
    #[serde(rename = "type")]
    pub console_call_type: String,
    pub args:              Vec<serde_json::Value>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TargetInfo {
    pub target_id: String,
    pub title:     String,
    pub url:       String,
    pub attached:  bool,

}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TargetAttachedToTargetResponse {
    pub session_id:           String,
    pub target_info:          TargetInfo,
    pub waiting_for_debugger: bool,
}

impl ConsoleAPICalledResponse {
    pub fn get_log_message(&self) -> String {
        let mut log_message = String::new();
        let mut is_first = true;
        for arg in &self.args {
            // Deserialize the `value` field if possible.
            // If not, just use the string representation of the value.
            if let Some(value) = arg.get("value") {
                let value = value.as_str().unwrap_or("");
                if is_first {
                    is_first = false;
                } else {
                    log_message.push(' ');
                }
                log_message.push_str(value);
            }
        }
        log_message
    }
}
