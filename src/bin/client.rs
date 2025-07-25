use std::{net::SocketAddr, time::Duration};

use clap::arg;
use hickory_proto::{op::Query, rr::RecordType, xfer::DnsRequestOptions};
use tracing::trace;
use tracing_subscriber::EnvFilter;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), ()> {
    tracing_subscriber::fmt()
        .compact()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cmd = clap::Command::new("walnut-client")
        .about("Simple UDP DNS Client")
        .arg(arg!(<ADDR> "Server to query").value_parser(clap::value_parser!(SocketAddr)))
        .arg(arg!(<QUERY> "DNS Name to query"))
        .arg(
            arg!([TYPE] "DNS record type to query")
                .value_parser(clap::value_parser!(RecordType))
                .default_value("A"),
        );

    let args = cmd.get_matches();
    let address = args
        .get_one::<SocketAddr>("ADDR")
        .expect("server is required");
    let query = args.get_one::<String>("QUERY").expect("query is required");
    let record_type = args
        .get_one::<RecordType>("TYPE")
        .expect("type is required");

    if let Err(error) = lookup(*address, query, *record_type).await {
        eprintln!("{error}");
        Err(())
    } else {
        Ok(())
    }
}

async fn lookup(
    address: SocketAddr,
    query: &str,
    record: RecordType,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = walnut_dns::client::Client::new_udp_client(address).await?;
    trace!("client constructed");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let query = Query::query(query.parse()?, record);
    trace!("client send request");
    let response = client.lookup(query, DnsRequestOptions::default()).await?;

    response.queries().iter().for_each(|query| {
        println!(
            "Query: {} {} {}",
            query.name(),
            query.query_class(),
            query.query_type()
        );
    });

    if response.answer_count() > 0 {
        println!("Answers:");
    }
    response.answers().iter().for_each(|answer| {
        println!(
            "{} {} {}",
            answer.name(),
            answer.record_type(),
            answer.data()
        )
    });

    Ok(())
}
