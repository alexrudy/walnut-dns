use std::fmt;

use hickory_proto::op::{Header, ResponseCode};
use hickory_server::{
    authority::MessageResponseBuilder,
    server::{Request, ResponseHandler, ResponseInfo},
};

pub(super) trait ResponseHandleExt {
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

pub(super) trait ResponseResultExt {
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
                ResponseInfo::serve_failed()
            }
        }
    }
}

pub(super) trait ResponseInfoExt: Sized {
    fn serve_failed() -> Self;
}

impl ResponseInfoExt for ResponseInfo {
    fn serve_failed() -> Self {
        let mut header = Header::new();
        header.set_response_code(ResponseCode::ServFail);
        header.into()
    }
}
