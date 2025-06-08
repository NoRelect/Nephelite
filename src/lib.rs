use kube::CustomResource;
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

#[derive(CustomResource, Debug, Serialize, Deserialize, Default, Clone, JsonSchema)]
#[kube(
    group = "nephelite.norelect.ch",
    version = "v2",
    kind = "Credential",
    namespaced,
    status = "CredentialStatus",
    shortname = "cred",
    doc = "Representation of a FIDO2 credential"
)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSpec {
    selector: Option<CredentialSelector>,
}

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum CredentialSelector {
    #[serde(rename_all = "camelCase")]
    YubiKey {
        model: String,
        serial_number: String,
    },
}

#[derive(Deserialize, Serialize, Clone, Default, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatus {
    pub public_keys: Vec<String>,
}
