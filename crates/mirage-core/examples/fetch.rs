//! cargo run -p mirage-core --example fetch -- <profile> <url>
use mirage_core::{Client, ClientOptions, Profile};

#[tokio::main]
async fn main() -> mirage_core::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let profile = args.get(1).map(String::as_str).unwrap_or("chrome");
    let url = args.get(2).map(String::as_str).unwrap_or("https://tls.peet.ws/api/all");
    let client = Client::new(ClientOptions::new(Profile::get(profile)?))?;
    let res = client.get(url).await?;
    eprintln!("{} {} ({})", res.version, res.status, res.url);
    println!("{}", res.text());
    Ok(())
}
