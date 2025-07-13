use std::fmt;

use hickory_proto::op::{Header, ResponseCode};
use hickory_server::{
    authority::MessageResponseBuilder,
    server::{Request, ResponseHandler, ResponseInfo},
};

pub(crate) trait ResponseHandleExt {
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

pub(crate) trait ResponseResultExt {
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

pub(crate) trait ResponseInfoExt: Sized {
    fn code_serve_failed() -> Self;
}

impl ResponseInfoExt for ResponseInfo {
    fn code_serve_failed() -> Self {
        let mut header = Header::new();
        header.set_response_code(ResponseCode::ServFail);
        header.into()
    }
}
