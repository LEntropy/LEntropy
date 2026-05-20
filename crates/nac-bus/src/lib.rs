use anyhow::Result;
use async_nats::Client;

pub struct NatsBus {
    client: Client,
}

impl NatsBus {
    pub async fn connect(url: &str) -> Result<Self> {
        let client = async_nats::connect(url).await?;
        Ok(Self { client })
    }

    pub async fn publish(&self, subject: &str, payload: Vec<u8>) -> Result<()> {
        self.client
            .publish(subject.to_string(), payload.into())
            .await?;
        Ok(())
    }
}
