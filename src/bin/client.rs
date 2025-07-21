use std::net::{Ipv4Addr, SocketAddr};

use clap::arg;
use hickory_proto::{op::Query, rr::RecordType, xfer::DnsRequestOptions};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), ()> {
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

    let bind = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));

    if let Err(error) = lookup(*address, bind, query, *record_type).await {
        eprintln!("{error}");
        Err(())
    } else {
        Ok(())
    }
}

async fn lookup(
    address: SocketAddr,
    bind: SocketAddr,
    query: &str,
    record: RecordType,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = walnut_dns::client::Client::new_udp_client(address, bind).await?;

    let query = Query::query(query.parse()?, record);
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
