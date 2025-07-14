use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

pub(crate) type Pool = bb8::Pool<RusqliteConnectionManager>;

/// Create a new SQLite connection pool
///
/// Creates a bb8 connection pool for SQLite databases with the specified
/// configuration. This enables concurrent access to the database.
///
/// # Arguments
///
/// * `path` - Path to the SQLite database file
/// * `timeout` - Busy timeout for database operations
///
/// # Returns
///
/// A new connection pool
///
/// # Errors
///
/// Returns an error if the pool cannot be created
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

/// Connection manager for SQLite databases
///
/// This manager handles the creation and lifecycle of SQLite database connections
/// for use with the bb8 connection pool. It provides configuration options for
/// database flags and timeouts.
#[derive(Debug, Clone)]
pub struct RusqliteConnectionManager {
    connection_options: Arc<ConnectionOptions>,
}

impl RusqliteConnectionManager {
    /// Set the busy timeout for database connections
    ///
    /// Configures how long database operations will wait when the database
    /// is locked before timing out.
    ///
    /// # Arguments
    ///
    /// * `timeout` - The timeout duration
    pub fn set_timeout(&mut self, timeout: Duration) {
        let config = Arc::make_mut(&mut self.connection_options);
        config.busy_timeout = timeout;
    }

    /// Create a new connection manager for the specified database path
    ///
    /// Creates a connection manager that will open SQLite databases at the
    /// specified path with default flags and a 500ms busy timeout.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the SQLite database file
    ///
    /// # Returns
    ///
    /// A new connection manager
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            connection_options: Arc::new(ConnectionOptions {
                path: path.as_ref().to_path_buf(),
                flags: None,
                busy_timeout: Duration::from_millis(500),
            }),
        }
    }

    /// Create a new connection manager with custom SQLite flags
    ///
    /// Creates a connection manager with custom SQLite open flags,
    /// allowing fine-grained control over database behavior.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the SQLite database file
    /// * `flags` - SQLite open flags to use
    ///
    /// # Returns
    ///
    /// A new connection manager with custom flags
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
