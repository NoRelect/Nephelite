use axum::{
    http::StatusCode,
    response::{Html, Json},
    routing::{get, post},
    Router,
};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use serde_cbor::from_slice;
use serde_cbor::value::Value;
use sha2::{Digest, Sha256};
use std::{env, str::FromStr};
use tokio::signal;
use tower_sessions::{cookie::time::Duration, Expiry, MemoryStore, Session, SessionManagerLayer};
use url::{Host, Url};
use x509_parser::{asn1_rs::Oid, prelude::*};

const REGISTER_HTML: &'static str = include_str!("html/register.html");
const YUBICO_ROOT_DER: &'static [u8] = include_bytes!("trust/yubico.der");

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(!cfg!(debug_assertions))
        .with_expiry(Expiry::OnInactivity(Duration::minutes(5)));

    let app = Router::new()
        .route("/", get(root))
        .route("/register", get(register))
        .route("/api/vendor-metadata", get(vendor_metadata))
        .route(
            "/api/registration/initialize",
            get(api_registration_initialize),
        )
        .route(
            "/api/registration/complete",
            post(api_registration_complete),
        )
        .layer(session_layer);

    let listener = tokio::net::TcpListener::bind("[::]:8000").await.unwrap();
    println!("Starting server on :8000");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
    println!("Stopping server...");
}

async fn root() -> &'static str {
    "Hello, World!"
}

async fn register() -> Html<&'static str> {
    Html(REGISTER_HTML)
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct FidoMetadataStatementList {
    pub legal_header: String,
    pub entries: Vec<MetadataEntry>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct MetadataEntry {
    pub aaguid: Option<String>,
    pub metadata_statement: MetadataStatement,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct MetadataStatement {
    pub aaguid: Option<String>,
    pub description: String,
}

async fn vendor_metadata() -> Json<FidoMetadataStatementList> {
    let vendor_metadata_json = std::fs::read("trust/vendor-metadata.json").unwrap();
    let fido_metadata_statements = serde_json::from_slice(&vendor_metadata_json).unwrap();
    return Json(fido_metadata_statements);
}

const CREDENTIAL_USER: &str = "cred";
const REGISTRATION_CHALLENGE: &str = "registration-challenge";

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct RegistrationOptions {
    pub rp_id: String,
    pub rp_name: String,
    pub attestation: String,
    pub challenge: String,
    pub user_display_name: String,
    pub user_name: String,
    pub user_id: String,
    pub pub_key_cred_params: Vec<PubKeyType>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct PubKeyType {
    pub alg: i32,
    pub r#type: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct RegistrationRequest {
    pub attestation_object: String,
    pub client_data: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct RegistrationResult {
    pub signature_counter: u32,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct AttestationObject {
    pub fmt: String,
    pub auth_data: Value,
    pub att_stmt: Value,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientData {
    challenge: String,
    origin: String,
    cross_origin: bool,
    r#type: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ErrorDetails {
    pub details: String,
}

fn get_rp_id() -> String {
    return match env::var("NEPHELITE_RP_ID") {
        Ok(rp_id) => rp_id,
        Err(_) => String::from("localhost"),
    };
}

async fn api_registration_initialize(session: Session) -> Json<RegistrationOptions> {
    let mut challenge = [0; 32];

    let mut rng = ChaCha20Rng::from_os_rng();
    rng.fill(&mut challenge);

    session
        .insert(&REGISTRATION_CHALLENGE, challenge.clone())
        .await
        .unwrap();
    Json(RegistrationOptions {
        rp_id: get_rp_id(),
        rp_name: String::from("Nephelite"),
        attestation: String::from("direct"),
        user_display_name: String::from(CREDENTIAL_USER),
        user_name: String::from(CREDENTIAL_USER),
        user_id: hex::encode(CREDENTIAL_USER),
        challenge: hex::encode(challenge),
        pub_key_cred_params: vec![PubKeyType {
            alg: -7,
            r#type: String::from("public-key"),
        }],
    })
}

fn bad_request(message: &str) -> (StatusCode, Json<ErrorDetails>) {
    return (
        StatusCode::BAD_REQUEST,
        Json(ErrorDetails {
            details: String::from(message),
        }),
    );
}

async fn api_registration_complete(
    session: Session,
    request: Json<RegistrationRequest>,
) -> Result<Json<RegistrationResult>, (StatusCode, Json<ErrorDetails>)> {
    // consume the challenge to ensure that it can't be replayed later.
    let challenge: [u8; 32] = match session
        .remove(&REGISTRATION_CHALLENGE)
        .await
        .unwrap_or_default()
    {
        Some(c) => c,
        _ => return Err(bad_request("Registration not initialized")),
    };

    let rp_id_hash = Sha256::digest(get_rp_id());

    let client_data_json = match hex::decode(&request.client_data) {
        Ok(c) => c,
        _ => return Err(bad_request("Client data could not be hex decoded")),
    };
    let client_data_hash = Sha256::digest(&client_data_json);
    let client_data: ClientData = match serde_json::from_slice(client_data_json.as_slice()) {
        Ok(c) => c,
        _ => return Err(bad_request("Invalid json in client data")),
    };

    if BASE64_URL_SAFE_NO_PAD
        .decode(client_data.challenge)
        .unwrap()
        != challenge
    {
        return Err(bad_request("Invalid challenge"));
    }

    let origin = match Url::parse(&client_data.origin) {
        Ok(o) => o,
        _ => return Err(bad_request("Origin is not a valid url")),
    };
    let origin_domain = match origin.host() {
        Some(Host::Domain(domain)) => domain,
        _ => return Err(bad_request("Invalid origin: No host")),
    };
    if origin_domain != get_rp_id() {
        return Err(bad_request(&format!(
            "Origin does not match rp id: {}",
            origin_domain
        )));
    }

    let attestation_object_cbor = match hex::decode(&request.attestation_object) {
        Ok(c) => c,
        _ => return Err(bad_request("Attestation data could not be hex decoded")),
    };
    let attestation_object: AttestationObject = from_slice(&attestation_object_cbor).unwrap();

    if attestation_object.fmt != "packed" {
        return Err(bad_request(&format!(
            "Unsupported attestation format: {}",
            attestation_object.fmt
        )));
    }

    let auth_data = match attestation_object.auth_data {
        Value::Bytes(b) => b,
        _ => return Err(bad_request("Authenticator data must be bytes")),
    };

    if auth_data.len() < 37 {
        return Err(bad_request("Authenticator data too short"));
    }

    if rp_id_hash[..] != auth_data[..32] {
        return Err(bad_request("Relaying party mismatch"));
    }

    let flags = auth_data[32];

    let mut signature_counter_bytes = [0; 4];
    signature_counter_bytes.copy_from_slice(&auth_data[33..37]);
    let signature_counter = u32::from_be_bytes(signature_counter_bytes);

    if (flags >> 6) & 1 != 1 {
        return Err(bad_request("No attested credential data present"));
    }

    let credential_id_length = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;

    let credential_id = Vec::from(&auth_data[55..(55 + credential_id_length)]);
    println!("credential_id: {}", hex::encode(credential_id));

    let credential_pub_key_bytes = Vec::from(&auth_data[(55 + credential_id_length)..]);
    let mut credential_pub_key = cose::keys::CoseKey::new();
    credential_pub_key.bytes = credential_pub_key_bytes;
    credential_pub_key.decode().unwrap();

    println!(
        "credential_pub_key: {:?} {:?}",
        credential_pub_key.kty, credential_pub_key.alg
    );

    let att_stmt = match attestation_object.att_stmt {
        Value::Map(m) => m,
        _ => return Err(bad_request("Invalid attestation statement")),
    };
    if att_stmt.get(&Value::Text(String::from("alg"))) != Some(&Value::Integer(-7)) {
        return Err(bad_request("Unsupported attestation signature algorithm"));
    }

    let x5c_cert_values = match att_stmt.get(&Value::Text(String::from("x5c"))) {
        Some(Value::Array(certs)) => certs,
        _ => return Err(bad_request("Invalid x5c field")),
    };
    let attestation_cert_bytes = match x5c_cert_values.first() {
        Some(Value::Bytes(b)) => b,
        _ => return Err(bad_request("Invalid attestation cert bytes")),
    };
    let attestation_cert = match X509Certificate::from_der(attestation_cert_bytes) {
        Ok(c) => c.1,
        _ => return Err(bad_request("Unable to parse attestation cert")),
    };
    let attestation_public_key = attestation_cert.public_key().parsed().unwrap();
    println!("Attestation pub key: {:?}", attestation_public_key);

    // Serial Number OID = 1.3.6.1.4.1.45724.1.1.2
    // AAGUID OID = 1.3.6.1.4.1.45724.1.1.4

    let aaguid_oid = Oid::from_str("1.3.6.1.4.1.45724.1.1.4").unwrap();
    let aaguid_ext = match attestation_cert.get_extension_unique(&aaguid_oid) {
        Ok(Some(ext)) => ext,
        _ => return Err(bad_request("Unable to get AAGUID cert extension")),
    };
    let aaguid = hex::encode(&aaguid_ext.value[2..]);
    println!("Attestation cert aaguid: {:?}", aaguid);
    println!("Attestation cert serial: {:?}", attestation_cert.serial);

    let root_ca = X509Certificate::from_der(YUBICO_ROOT_DER).unwrap().1;
    let root_public_key = root_ca.public_key();

    if !attestation_cert
        .verify_signature(Some(root_public_key))
        .is_ok()
    {
        return Err(bad_request("Attestation certificate signature invalid"));
    }
    // We can now trust the attestation certificate public key to sign the newly created credential data

    let signature = match att_stmt.get(&Value::Text(String::from("sig"))) {
        Some(Value::Bytes(b)) => b,
        _ => return Err(bad_request("Invalid signature bytes")),
    };
    // TODO: Check signature with attestation_public_key

    return Ok(Json(RegistrationResult { signature_counter }));
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
