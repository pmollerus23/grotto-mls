#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    grotto_relay::run().await
}
