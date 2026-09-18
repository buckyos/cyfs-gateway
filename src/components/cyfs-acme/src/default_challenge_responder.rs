use crate::{AcmeCertManager, AcmeChallengeResponder, Challenge};
use std::sync::{Arc, Weak};

pub(crate) struct DefaultChallengeResponder {
    cert_mgr: Weak<AcmeCertManager>,
}

impl DefaultChallengeResponder {
    pub fn new(cert_mgr: Arc<AcmeCertManager>) -> DefaultChallengeResponder {
        DefaultChallengeResponder {
            cert_mgr: Arc::downgrade(&cert_mgr),
        }
    }
}

#[async_trait::async_trait]
impl AcmeChallengeResponder for DefaultChallengeResponder {
    async fn respond_challenge<'a>(
        &self,
        challenges: &'a [Challenge],
    ) -> anyhow::Result<&'a Challenge> {
        if let Some(cert_mgr) = self.cert_mgr.upgrade() {
            cert_mgr.respond_challenge(challenges).await
        } else {
            Err(anyhow::anyhow!("cert_mgr is gone"))
        }
    }

    fn propagation_delay(&self, challenge: &Challenge) -> std::time::Duration {
        self.cert_mgr
            .upgrade()
            .map(|cert_mgr| cert_mgr.challenge_propagation_delay(challenge))
            .unwrap_or(std::time::Duration::ZERO)
    }

    fn revert_challenge(&self, challenge: &Challenge) {
        if let Some(cert_mgr) = self.cert_mgr.upgrade() {
            cert_mgr.revert_challenge(challenge);
        }
    }
}
