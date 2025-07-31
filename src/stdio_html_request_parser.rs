#[derive(Clone, Debug, PartialEq)]
pub enum StdioRequest {
    ConsoleOutput(String),
    ConsoleError(String),
    IgnoredRequest,
    PageLoad,
    ExitRequest
}

#[derive(Clone, Debug, PartialEq)]
pub enum StdioRequestParseError {
    UnknownRequest(String),
    InvalidRequest(String)
}

#[derive(Clone, Debug)]
pub struct StdioParsingOptions{
    pub parse_stdio_output: bool,
}

pub fn parse_request(options: &StdioParsingOptions, request: &[u8]) -> Result<StdioRequest, StdioRequestParseError> {
    if request.starts_with(b"^out^") {
        if options.parse_stdio_output {
            let parts = request.split(|b| *b == b'^').collect::<Vec<_>>();
            if parts.len() < 4 {
                let lossy_string = String::from_utf8_lossy(request).to_string();
                return Err(StdioRequestParseError::InvalidRequest(lossy_string));
            }
            let out = percent_encoding::percent_decode(parts[3]).decode_utf8_lossy();
            Ok(StdioRequest::ConsoleOutput(out.to_string()))
        } else {
            Ok(StdioRequest::IgnoredRequest)
        }
    } else if request.starts_with(b"^err^") {
        if options.parse_stdio_output {
            let parts = request.split(|b| *b == b'^').collect::<Vec<_>>();
            if parts.len() < 4 {
                let lossy_string = String::from_utf8_lossy(request).to_string();
                return Err(StdioRequestParseError::InvalidRequest(lossy_string));
            }
            let err = percent_encoding::percent_decode(parts[3]).decode_utf8_lossy();
            Ok(StdioRequest::ConsoleError(err.to_string()))
        } else {
            Ok(StdioRequest::IgnoredRequest)
        }
    } else if request.starts_with(b"^exit^") {
        Ok(StdioRequest::ExitRequest)
    } else if request.starts_with(b"^pageload^") {
        Ok(StdioRequest::PageLoad)
    } else {
        Err(StdioRequestParseError::UnknownRequest(String::from_utf8_lossy(request).to_string()))
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn test_parse_request() {
        use super::*;
        let options = StdioParsingOptions {
            parse_stdio_output: true
        };

        let request = b"^out^1^Hello%20World!";
        let result = parse_request(&options, request).unwrap();
        assert_eq!(result, StdioRequest::ConsoleOutput("Hello World!".to_string()));

        let request = b"^err^9001^Hello%20World!";
        let result = parse_request(&options, request).unwrap();
        assert_eq!(result, StdioRequest::ConsoleError("Hello World!".to_string()));

        let request = b"^exit^";
        let result = parse_request(&options, request).unwrap();
        assert_eq!(result, StdioRequest::ExitRequest);

        let request = b"^pageload^";
        let result = parse_request(&options, request).unwrap();
        assert_eq!(result, StdioRequest::PageLoad);

        let request = b"^unknown^";
        let result = parse_request(&options, request);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_request_no_output() {
        use super::*;
        let options = StdioParsingOptions {
            parse_stdio_output: false
        };

        let request = b"^out^1^Hello%20World!";
        let result = parse_request(&options, request).unwrap();
        assert_eq!(result, StdioRequest::IgnoredRequest);

        let request = b"^err^9001^Hello%20World!";
        let result = parse_request(&options, request).unwrap();
        assert_eq!(result, StdioRequest::IgnoredRequest);

        let request = b"^exit^";
        let result = parse_request(&options, request).unwrap();
        assert_eq!(result, StdioRequest::ExitRequest);

        let request = b"^pageload^";
        let result = parse_request(&options, request).unwrap();
        assert_eq!(result, StdioRequest::PageLoad);

        let request = b"^unknown^";
        let result = parse_request(&options, request);
        assert!(result.is_err());
    }
}