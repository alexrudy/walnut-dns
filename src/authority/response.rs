//! DNS response handling utilities
//!
//! This module provides extension traits and helper functions for handling DNS responses,
//! error cases, and response information processing. These utilities simplify error
//! handling and response generation throughout the DNS server implementation.

use std::fmt;

use hickory_proto::op::{Header, ResponseCode};
use hickory_server::{
    authority::MessageResponseBuilder,
    server::{Request, ResponseHandler, ResponseInfo},
};

/// Extension trait for DNS response handlers to send error responses
/// 
/// This trait provides a convenient method for sending DNS error responses
/// with appropriate response codes. It simplifies error handling by providing
/// a standardized way to generate error responses.
pub(crate) trait ResponseHandleExt {
    /// Send an error response to the client
    /// 
    /// Generates and sends a DNS error response with the specified response code.
    /// The response maintains the same ID and query information as the original
    /// request while setting the appropriate error code.
    /// 
    /// # Arguments
    /// 
    /// * `request` - The original DNS request that caused the error
    /// * `code` - The DNS response code to send (e.g., FormErr, ServFail, NXDomain)
    /// 
    /// # Returns
    /// 
    /// Information about the response that was sent
    async fn send_error(&mut self, request: &Request, code: ResponseCode) -> ResponseInfo;
}

impl<R> ResponseHandleExt for R
where
    R: ResponseHandler,
{
    async fn send_error(&mut self, request: &Request, code: ResponseCode) -> ResponseInfo {
        tracing::trace!("REPLY error {code}");
        let response = MessageResponseBuilder::from_message_request(request);
        self.send_response(response.error_msg(request.header(), code))
            .await
            .into_info()
    }
}

/// Extension trait for converting response results to response info
/// 
/// This trait provides a convenient way to convert Result types from response
/// operations into ResponseInfo, handling errors gracefully by logging them
/// and returning appropriate server failure responses.
pub(crate) trait ResponseResultExt {
    /// Convert a result to response info
    /// 
    /// Converts a Result from a response operation into ResponseInfo.
    /// On success, returns the response info directly. On error, logs
    /// the error and returns a server failure response.
    /// 
    /// # Returns
    /// 
    /// ResponseInfo indicating the outcome of the operation
    fn into_info(self) -> ResponseInfo;
}

impl<E> ResponseResultExt for Result<ResponseInfo, E>
where
    E: fmt::Display,
{
    fn into_info(self) -> ResponseInfo {
        match self {
            Ok(info) => info,
            Err(error) => {
                tracing::error!("Sending DNS response failed: {error}");
                ResponseInfo::code_serve_failed()
            }
        }
    }
}

/// Extension trait for creating response info with specific error codes
/// 
/// This trait provides convenient methods for creating ResponseInfo instances
/// with specific DNS response codes, particularly for server error conditions.
pub(crate) trait ResponseInfoExt: Sized {
    /// Create a server failure response
    /// 
    /// Creates a ResponseInfo instance with a ServFail response code,
    /// indicating that the server encountered an internal error while
    /// processing the request.
    /// 
    /// # Returns
    /// 
    /// ResponseInfo with ServFail response code
    fn code_serve_failed() -> Self;
}

impl ResponseInfoExt for ResponseInfo {
    fn code_serve_failed() -> Self {
        let mut header = Header::new();
        header.set_response_code(ResponseCode::ServFail);
        header.into()
    }
}
