// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fresh native genesis with the principal name used by public-bus fixture selectors.
use super::*;
impl Fixture {
    pub(crate) async fn with_principal(
        id: &str,
        device: &str,
        principal: &str,
    ) -> TestResult<Self> {
        let root = Root::new()?;
        let vault = Arc::new(TestVault::default());
        Box::pin(Self::with_principal_in(root, vault, id, device, principal)).await
    }
    pub(crate) async fn peer_at_same_home(
        &self,
        id: &str,
        device: &str,
        principal: &str,
    ) -> TestResult<Self> {
        Box::pin(Self::with_principal_in(
            Root(self.root.0.clone()),
            self.vault.clone(),
            id,
            device,
            principal,
        ))
        .await
    }
    async fn with_principal_in(
        root: Root,
        vault: Arc<TestVault>,
        id: &str,
        device: &str,
        principal: &str,
    ) -> TestResult<Self> {
        let now = crate::custody::network_now()?;
        let mut input = crate::custody::tests::input(id);
        input.principal_id = principal.into();
        input.device_id = device.into();
        let mut ceremony = crate::custody::CreationCeremony::begin(&root.0, input, now)?;
        let phrase = ceremony.show_once()?;
        let positions = ceremony.hidden_challenge()?;
        let account = ceremony.confirm(
            &crate::custody::tests::words(&phrase, positions)?,
            vault.as_ref(),
            now,
        )?;
        Self::finish_creation(root, vault, id, device, account.record().clone()).await
    }
}
