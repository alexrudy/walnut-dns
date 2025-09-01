pub mod authority;
pub mod cache;
pub mod catalog;
pub mod client;
pub mod codec;
pub mod database;
pub mod error;
pub mod rr;
pub mod server;
pub mod services;

pub use self::authority::{Lookup, ZoneInfo};
pub use self::catalog::Catalog;
pub use self::database::{SqliteConfiguration, SqliteStore};

pub(crate) fn block_in_place<R, F: FnOnce() -> R>(f: F) -> R {
    #[cfg(not(feature = "pool"))]
    {
        f()
    }
    #[cfg(feature = "pool")]
    {
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            match rt.runtime_flavor() {
                tokio::runtime::RuntimeFlavor::CurrentThread => f(),
                tokio::runtime::RuntimeFlavor::MultiThread => tokio::task::block_in_place(f),
                _ => f(),
            }
        } else {
            f()
        }
    }
}

#[cfg(test)]
/// Registers a global default tracing subscriber when called for the first time. This is intended
/// for use in tests.
pub(crate) fn subscribe() {
    use std::sync::Once;
    static INSTALL_TRACING_SUBSCRIBER: Once = Once::new();
    INSTALL_TRACING_SUBSCRIBER.call_once(|| {
        let subscriber = tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();
    });
}
