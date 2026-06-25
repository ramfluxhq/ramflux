#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;

pub(crate) async fn handle_a2ui(socket: PathBuf, command: A2uiCommand) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(socket).await?;
    match command.action {
        A2uiAction::Render(render) => {
            let surface = serde_json::from_slice(&std::fs::read(render.surface)?)?;
            let request = LocalBusA2uiRenderRequest {
                surface,
                supported_catalogs: render.supported_catalog,
                granted_permissions: render.permission,
            };
            print_json(&bus.request(Some(render.account), "a2ui", "a2ui.render", &request).await?)
        }
        A2uiAction::Action(action) => {
            let request = LocalBusA2uiActionRequest {
                surface: serde_json::from_slice(&std::fs::read(action.surface)?)?,
                action: serde_json::from_slice(&std::fs::read(action.action)?)?,
            };
            print_json(&bus.request(Some(action.account), "a2ui", "a2ui.action", &request).await?)
        }
    }
}
