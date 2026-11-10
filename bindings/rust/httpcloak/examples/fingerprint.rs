//! Shows the fingerprint a server sees, from tls.peet.ws.
//!
//! cargo run --example fingerprint [preset]

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let preset = std::env::args().nth(1).unwrap_or_else(|| httpcloak::presets::CHROME_LATEST.to_string());
    let session = httpcloak::Session::builder().preset(&preset).build()?;

    let response = session.get("https://tls.peet.ws/api/all").send()?.error_for_status()?;
    let seen: serde_json::Value = response.json()?;

    println!("httpcloak {} as {preset}", httpcloak::version());
    println!("protocol:   {:?} in {:?}", response.version(), response.elapsed());
    println!("user agent: {}", seen["user_agent"].as_str().unwrap_or("?"));
    println!("ja4:        {}", seen["tls"]["ja4"].as_str().unwrap_or("?"));
    println!("akamai:     {}", seen["http2"]["akamai_fingerprint"].as_str().unwrap_or("-"));
    Ok(())
}
