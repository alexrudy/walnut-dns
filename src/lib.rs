pub mod authority;
pub mod catalog;
pub mod database;
pub mod rr;

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
