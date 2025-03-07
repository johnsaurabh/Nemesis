struct Reaper {
    honeypot: Honeypot,
    bastion_client: BastionClient,
}

impl Reaper {
    async fn neutralize(&self, threat: Threat) {
        if threat.severity > 0.8 {
            self.bastion_client.ban_ip(threat.ip).await;
            self.honeypot.serve_fake_data(threat.ip).await;
        }
    }
}