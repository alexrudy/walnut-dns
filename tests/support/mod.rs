#![allow(unused)]

use std::collections::BTreeMap;
use std::future::poll_fn;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::task::Poll;

use futures::FutureExt as _;
use hickory_proto::serialize::binary::BinDecodable as _;
use hickory_proto::{
    op::Message,
    rr::Record,
    serialize::binary::{BinDecoder, BinEncoder},
};
use hickory_server::{
    authority::MessageResponse,
    server::{ResponseHandler, ResponseInfo},
};
use walnut_dns::catalog::CatalogError;
use walnut_dns::catalog::CatalogStore;
use walnut_dns::rr::{LowerName, Name};

pub mod examples;

/// Registers a global default tracing subscriber when called for the first time. This is intended
/// for use in tests.
pub fn subscribe() {
    static INSTALL_TRACING_SUBSCRIBER: Once = Once::new();
    INSTALL_TRACING_SUBSCRIBER.call_once(|| {
        let subscriber = tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();
    });
}

#[derive(Clone, Default)]
pub struct TestResponseHandler {
    message_ready: Arc<AtomicBool>,
    buf: Arc<Mutex<Vec<u8>>>,
}

impl TestResponseHandler {
    pub fn new() -> Self {
        let buf = Arc::new(Mutex::new(Vec::with_capacity(512)));
        let message_ready = Arc::new(AtomicBool::new(false));
        TestResponseHandler { message_ready, buf }
    }

    fn into_inner(self) -> impl Future<Output = Vec<u8>> {
        poll_fn(move |_| {
            if self
                .message_ready
                .compare_exchange(true, false, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                let bytes: Vec<u8> = std::mem::take(&mut self.buf.lock().unwrap());
                Poll::Ready(bytes)
            } else {
                Poll::Pending
            }
        })
    }

    pub fn into_message(self) -> impl Future<Output = Message> {
        let bytes = self.into_inner();
        bytes.map(|b| {
            let mut decoder = BinDecoder::new(&b);
            Message::read(&mut decoder).expect("could not decode message")
        })
    }
}

#[async_trait::async_trait]
impl ResponseHandler for TestResponseHandler {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> io::Result<ResponseInfo> {
        let buf = &mut self.buf.lock().unwrap();
        buf.clear();
        let mut encoder = BinEncoder::new(buf);
        let info = response
            .destructive_emit(&mut encoder)
            .expect("could not encode");
        self.message_ready.store(true, Ordering::Release);
        Ok(info)
    }
}

pub struct TestZoneStore<Z> {
    zones: Mutex<BTreeMap<LowerName, Vec<Z>>>,
}

impl<Z> TestZoneStore<Z> {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            zones: Mutex::new(BTreeMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl<Z: Clone + Send + Sync> CatalogStore<Z> for TestZoneStore<Z> {
    async fn find(
        &self,
        origin: &walnut_dns::rr::LowerName,
    ) -> Result<Option<Vec<Z>>, CatalogError> {
        let data = self.zones.lock().expect("poisoned");
        let mut name = origin.clone();
        loop {
            tracing::trace!("Looking for {name}");
            if let Some(zones) = data.get(&name) {
                return Ok(Some(zones.clone()));
            }
            if !name.is_root() {
                name = name.base_name();
            } else {
                return Ok(None);
            }
        }
    }

    async fn upsert(
        &self,
        name: walnut_dns::rr::LowerName,
        zones: &[Z],
    ) -> Result<(), CatalogError> {
        let mut data = self.zones.lock().expect("poisoned");
        data.insert(name, zones.to_vec());
        Ok(())
    }

    async fn list(&self) -> Result<Vec<Name>, CatalogError> {
        let data = self.zones.lock().expect("poisoned");
        Ok(data.keys().cloned().map(Into::into).collect())
    }

    async fn remove(
        &self,
        name: &walnut_dns::rr::LowerName,
    ) -> Result<Option<Vec<Z>>, CatalogError> {
        let mut data = self.zones.lock().expect("poisoned");
        Ok(data.remove(name))
    }
}
