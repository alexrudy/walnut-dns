use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

pub(crate) type Pool = bb8::Pool<RusqliteConnectionManager>;

pub(crate) async fn pool(
    path: impl AsRef<Path>,
    timeout: Duration,
) -> Result<Pool, rusqlite::Error> {
    let mut manager = RusqliteConnectionManager::new(path);
    manager.set_timeout(timeout);
    bb8::Pool::builder()
        .test_on_check_out(false)
        .build(manager)
        .await
}

#[derive(Debug, Clone)]
pub struct RusqliteConnectionManager {
    connection_options: Arc<ConnectionOptions>,
}

impl RusqliteConnectionManager {
    pub fn set_timeout(&mut self, timeout: Duration) {
        let config = Arc::make_mut(&mut self.connection_options);
        config.busy_timeout = timeout;
    }

    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            connection_options: Arc::new(ConnectionOptions {
                path: path.as_ref().to_path_buf(),
                flags: None,
                busy_timeout: Duration::from_millis(500),
            }),
        }
    }

    pub fn new_with_flags(path: impl AsRef<Path>, flags: rusqlite::OpenFlags) -> Self {
        Self {
            connection_options: Arc::new(ConnectionOptions {
                path: path.as_ref().to_path_buf(),
                flags: Some(flags),
                busy_timeout: Duration::from_millis(500),
            }),
        }
    }
}

#[derive(Debug, Clone)]
struct ConnectionOptions {
    path: PathBuf,
    flags: Option<rusqlite::OpenFlags>,
    busy_timeout: Duration,
}

impl ConnectionOptions {
    fn open(&self) -> rusqlite::Result<rusqlite::Connection> {
        if let Some(flags) = self.flags {
            rusqlite::Connection::open_with_flags(&self.path, flags)
        } else {
            rusqlite::Connection::open(&self.path)
        }
    }
}

#[async_trait::async_trait]
impl bb8::ManageConnection for RusqliteConnectionManager {
    type Connection = rusqlite::Connection;
    type Error = rusqlite::Error;

    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        crate::block_in_place(|| {
            let conn = self.connection_options.open()?;

            conn.pragma_update(None, "foreign_keys", true)?;
            conn.pragma_update(None, "journal_mode", "WAL")?;
            conn.pragma_update(
                None,
                "busy_timeout",
                self.connection_options.busy_timeout.as_millis() as u64,
            )?;
            Ok(conn)
        })
    }

    async fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        crate::block_in_place(|| conn.execute("SELECT 1", [])).map(|_| ())
    }

    fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
        false
    }
}
