use serde_cbor::from_slice;
use serde_cbor::value::Value;
use axum::{response::{Html, Json}, routing::{get, post}, Router};
use rand::SeedableRng;
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use tokio::signal;
use tower_sessions::{cookie::time::Duration, Expiry, MemoryStore, Session, SessionManagerLayer};

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
        .route("/api/registration/initialize", get(api_registration_initialize))
        .route("/api/registration/complete", post(api_registration_complete))
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
    Html(include_str!("html/register.html"))
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
    pub attestation_object: String
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct RegistrationResult {
    pub success: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct AttestationObject {
    pub fmt: String,
}

async fn api_registration_initialize(session: Session) -> Json<RegistrationOptions> {
    let mut challenge = [0; 32];

    let mut rng = ChaCha20Rng::from_os_rng();
    rng.fill(&mut challenge);

    session.insert(&REGISTRATION_CHALLENGE, challenge.clone()).await.unwrap();
    Json(RegistrationOptions{
        rp_id: String::from("localhost"),
        rp_name: String::from("Nephelite"),
        attestation: String::from("direct"),
        user_display_name: String::from(CREDENTIAL_USER),
        user_name: String::from(CREDENTIAL_USER),
        user_id: hex::encode(CREDENTIAL_USER),
        challenge: hex::encode(challenge),
        pub_key_cred_params: vec![
            PubKeyType {
                alg: -7,
                r#type: String::from("public-key")
            }
        ]
    })
}

async fn api_registration_complete(session: Session, body: Json<RegistrationRequest>) -> Json<RegistrationResult> {
    let attestation_object_cbor = hex::decode(&body.attestation_object).unwrap();
    let value: Value = from_slice(&attestation_object_cbor).unwrap();

    println!("{:?}", value);

    let attestation_object: AttestationObject = from_slice(&attestation_object_cbor).unwrap();
    println!("{:?}", attestation_object);

    let session_challenge: Option<[u8; 32]> = session.get(&REGISTRATION_CHALLENGE).await.unwrap_or_default();
    if session_challenge == None {
        return Json(RegistrationResult { success: false })
    }

    let challenge: [u8; 32] = session_challenge.unwrap();
    Json(RegistrationResult {
        success: true
    })
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