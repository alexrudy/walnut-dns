/// Trait for deserializing objects from SQLite rows
///
/// This trait provides a way to construct objects from SQLite query results.
/// It's used throughout the database layer to convert raw row data into
/// strongly-typed Rust structures.
pub trait FromRow {
    /// Create an instance from a SQLite row
    ///
    /// Extracts the necessary data from the provided row and constructs
    /// a new instance of the implementing type.
    ///
    /// # Arguments
    ///
    /// * `row` - The SQLite row containing the data
    ///
    /// # Returns
    ///
    /// A new instance of the implementing type
    ///
    /// # Errors
    ///
    /// Returns an error if the row data cannot be converted to the expected type
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self>
    where
        Self: Sized;
}
