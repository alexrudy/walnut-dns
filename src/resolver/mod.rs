use hickory_proto::op::Query;

mod lookup;
pub mod reserved;

pub use lookup::QueryLookup;

pub type ResolverError = Box<dyn std::error::Error + Send + Sync>;

#[async_trait::async_trait]
pub trait Resolver {
    /// Query this resolver for a name.
    async fn query(&self, query: Query) -> Result<QueryLookup, ResolverError>;
}
