use std::{env, sync::Arc};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use libp2p_identity::PublicKey;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tower_http::limit::RequestBodyLimitLayer;

struct AppState {
    db: SqlitePool,
}

#[derive(Deserialize)]
struct RegisterRequest {
    public_key: String,
    message: String,
    signature: String,
}

#[derive(Serialize)]
struct PeerResponse {
    peer_id: String,
    username: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
}

#[derive(Deserialize)]
struct FindQuery {
    q: Option<String>,
}

fn error_json(msg: &str) -> Json<ErrorResponse> {
    Json(ErrorResponse {
        error: msg.to_string(),
    })
}

async fn register(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RegisterRequest>,
) -> impl IntoResponse {
    tracing::info!("POST /register");
    let public_key_bytes = match BASE64.decode(&body.public_key) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                error_json("invalid base64 public_key"),
            )
                .into_response()
        }
    };

    let signature_bytes = match BASE64.decode(&body.signature) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                error_json("invalid base64 signature"),
            )
                .into_response()
        }
    };

    let payload: serde_json::Value = match serde_json::from_str(&body.message) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                error_json("message must be a JSON string containing username"),
            )
                .into_response()
        }
    };

    let username = match payload.get("username").and_then(|v| v.as_str()) {
        Some(u) if !u.trim().is_empty() => u.trim().to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                error_json("message.username is required"),
            )
                .into_response()
        }
    };

    let public_key = match PublicKey::try_decode_protobuf(&public_key_bytes) {
        Ok(k) => k,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                error_json("public_key, message, and signature are required strings"),
            )
                .into_response()
        }
    };

    let message_bytes = body.message.as_bytes();
    if !public_key.verify(message_bytes, &signature_bytes) {
        return (StatusCode::UNAUTHORIZED, error_json("invalid signature")).into_response();
    }

    let peer_id = libp2p_identity::PeerId::from_public_key(&public_key).to_base58();

    // Check if peer_id already exists
    let existing_peer = sqlx::query_scalar::<_, String>(
        "SELECT username FROM peers WHERE peer_id = ? LIMIT 1",
    )
    .bind(&peer_id)
    .fetch_optional(&state.db)
    .await;

    match existing_peer {
        Ok(Some(_old_username)) => {
            // Peer_id exists, update the username
            // But first check if the new username is taken by a different peer_id
            let username_taken_by_other = sqlx::query_scalar::<_, String>(
                "SELECT peer_id FROM peers WHERE username = ? AND peer_id != ? LIMIT 1",
            )
            .bind(&username)
            .bind(&peer_id)
            .fetch_optional(&state.db)
            .await;

            match username_taken_by_other {
                Ok(Some(_)) => {
                    return (
                        StatusCode::CONFLICT,
                        error_json("username already taken by another peer"),
                    )
                        .into_response()
                }
                Err(e) => {
                    tracing::error!("register error: {e}");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        error_json("internal server error"),
                    )
                        .into_response();
                }
                Ok(None) => {}
            }

            // Update the username for this peer_id
            if let Err(e) = sqlx::query("UPDATE peers SET username = ? WHERE peer_id = ?")
                .bind(&username)
                .bind(&peer_id)
                .execute(&state.db)
                .await
            {
                tracing::error!("register error: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error_json("internal server error"),
                )
                    .into_response();
            }

            return (StatusCode::OK, Json(PeerResponse { peer_id, username })).into_response();
        }
        Err(e) => {
            tracing::error!("register error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                error_json("internal server error"),
            )
                .into_response();
        }
        Ok(None) => {}
    }

    // Peer_id doesn't exist, check if username is taken
    let username_exists = sqlx::query_scalar::<_, String>(
        "SELECT peer_id FROM peers WHERE username = ? LIMIT 1",
    )
    .bind(&username)
    .fetch_optional(&state.db)
    .await;

    match username_exists {
        Ok(Some(_)) => {
            return (
                StatusCode::CONFLICT,
                error_json("username already registered"),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("register error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                error_json("internal server error"),
            )
                .into_response();
        }
        Ok(None) => {}
    }

    // Insert new peer
    let now = chrono::Utc::now().to_rfc3339();
    if let Err(e) = sqlx::query(
        "INSERT INTO peers (peer_id, username, public_key, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(&peer_id)
    .bind(&username)
    .bind(&public_key_bytes)
    .bind(&now)
    .execute(&state.db)
    .await
    {
        tracing::error!("register error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            error_json("internal server error"),
        )
            .into_response();
    }

    (
        StatusCode::CREATED,
        Json(PeerResponse { peer_id, username }),
    )
        .into_response()
}

async fn health() -> Json<HealthResponse> {
    tracing::info!("GET /health");
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

async fn find_by_name(
    State(state): State<Arc<AppState>>,
    Query(params): Query<FindQuery>,
) -> impl IntoResponse {
    tracing::info!("GET /find-by-name");
    let query = params.q.unwrap_or_default().trim().to_string();

    if query.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            error_json("q query parameter is required"),
        )
            .into_response();
    }

    let row = sqlx::query_as::<_, (String, String)>(
        "SELECT peer_id, username FROM peers WHERE username = ? LIMIT 1",
    )
    .bind(&query)
    .fetch_optional(&state.db)
    .await;

    match row {
        Ok(Some((peer_id, username))) => Json(PeerResponse { peer_id, username }).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, error_json("peer not found")).into_response(),
        Err(e) => {
            tracing::error!("find-by-name error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                error_json("internal server error"),
            )
                .into_response()
        }
    }
}

async fn find_by_id(
    State(state): State<Arc<AppState>>,
    Query(params): Query<FindQuery>,
) -> impl IntoResponse {
    tracing::info!("GET /find-by-id");
    let query = params.q.unwrap_or_default().trim().to_string();

    if query.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            error_json("q query parameter is required"),
        )
            .into_response();
    }

    let row = sqlx::query_as::<_, (String, String)>(
        "SELECT peer_id, username FROM peers WHERE peer_id = ? LIMIT 1",
    )
    .bind(&query)
    .fetch_optional(&state.db)
    .await;

    match row {
        Ok(Some((peer_id, username))) => Json(PeerResponse { peer_id, username }).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, error_json("peer not found")).into_response(),
        Err(e) => {
            tracing::error!("find-by-id error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                error_json("internal server error"),
            )
                .into_response()
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8000);

    let db_path = env::var("DB_PATH").unwrap_or_else(|_| "data/peers.db".to_string());

    std::fs::create_dir_all(
        std::path::Path::new(&db_path)
            .parent()
            .unwrap_or(std::path::Path::new(".")),
    )
    .ok();

    let db_url = format!("sqlite:{}?mode=rwc", db_path);
    let db = SqlitePool::connect(&db_url)
        .await
        .expect("failed to connect to database");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS peers (
            peer_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            public_key BLOB NOT NULL,
            created_at TEXT NOT NULL
        )",
    )
    .execute(&db)
    .await
    .expect("failed to create table");

    let state = Arc::new(AppState { db });
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("failed to bind");

    println!("server listening on http://localhost:{port}");

    axum::serve(listener, app).await.expect("server error");
}

fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/register", post(register))
        .route("/health", get(health))
        .route("/find-by-name", get(find_by_name))
        .route("/find-by-id", get(find_by_id))
        .layer(RequestBodyLimitLayer::new(32 * 1024))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use http::Request;
    use rand::RngCore;
    use tower::ServiceExt;

    fn generate_keypair() -> libp2p_identity::Keypair {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        libp2p_identity::Keypair::ed25519_from_bytes(bytes).unwrap()
    }

    async fn setup() -> Router {
        let db = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("failed to connect");

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS peers (
                peer_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                public_key BLOB NOT NULL,
                created_at TEXT NOT NULL
            )",
        )
        .execute(&db)
        .await
        .expect("failed to create table");

        build_router(Arc::new(AppState { db }))
    }

    fn generate_register_body(username: &str) -> serde_json::Value {
        let keypair = generate_keypair();
        let public_key = keypair.public().encode_protobuf();
        let message = serde_json::json!({ "username": username }).to_string();
        let signature = keypair.sign(message.as_bytes()).expect("signing failed");

        serde_json::json!({
            "public_key": BASE64.encode(&public_key),
            "message": message,
            "signature": BASE64.encode(&signature),
        })
    }

    async fn response_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    // -- /health --

    #[tokio::test]
    async fn health_returns_ok() {
        let app = setup().await;

        let response = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["status"], "ok");
    }

    // -- POST /register --

    #[tokio::test]
    async fn register_success() {
        let app = setup().await;
        let body = generate_register_body("alice");

        let response = app
            .oneshot(
                Request::post("/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let json = response_json(response).await;
        assert_eq!(json["username"], "alice");
        assert!(json["peer_id"].is_string());
    }

    #[tokio::test]
    async fn register_same_peer_updates_username() {
        let app = setup().await;

        // Use the same keypair for both requests
        let keypair = generate_keypair();
        let public_key = keypair.public().encode_protobuf();
        let peer_id = libp2p_identity::PeerId::from_public_key(&keypair.public()).to_base58();

        // First registration with username "alice"
        let message1 = serde_json::json!({ "username": "alice" }).to_string();
        let signature1 = keypair.sign(message1.as_bytes()).expect("signing failed");
        let body1 = serde_json::json!({
            "public_key": BASE64.encode(&public_key),
            "message": message1,
            "signature": BASE64.encode(&signature1),
        });

        let resp = app
            .clone()
            .oneshot(
                Request::post("/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body1.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let json = response_json(resp).await;
        assert_eq!(json["username"], "alice");
        assert_eq!(json["peer_id"], peer_id);

        // Second registration with same peer_id but username "alice_updated"
        let message2 = serde_json::json!({ "username": "alice_updated" }).to_string();
        let signature2 = keypair.sign(message2.as_bytes()).expect("signing failed");
        let body2 = serde_json::json!({
            "public_key": BASE64.encode(&public_key),
            "message": message2,
            "signature": BASE64.encode(&signature2),
        });

        let resp = app
            .oneshot(
                Request::post("/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body2.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 200 OK (not 201 CREATED)
        assert_eq!(resp.status(), StatusCode::OK);
        let json = response_json(resp).await;
        assert_eq!(json["username"], "alice_updated");
        assert_eq!(json["peer_id"], peer_id);
    }

    #[tokio::test]
    async fn register_same_peer_cannot_take_existing_username() {
        let app = setup().await;

        // Register first peer with username "carol"
        let body1 = generate_register_body("carol");
        let resp = app
            .clone()
            .oneshot(
                Request::post("/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body1.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Register second peer with username "dave"
        let keypair2 = generate_keypair();
        let public_key2 = keypair2.public().encode_protobuf();
        let message2 = serde_json::json!({ "username": "dave" }).to_string();
        let signature2 = keypair2.sign(message2.as_bytes()).expect("signing failed");
        let body2 = serde_json::json!({
            "public_key": BASE64.encode(&public_key2),
            "message": message2,
            "signature": BASE64.encode(&signature2),
        });

        let resp = app
            .clone()
            .oneshot(
                Request::post("/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body2.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Try to update second peer's username to "carol" (already taken by first peer)
        let message3 = serde_json::json!({ "username": "carol" }).to_string();
        let signature3 = keypair2.sign(message3.as_bytes()).expect("signing failed");
        let body3 = serde_json::json!({
            "public_key": BASE64.encode(&public_key2),
            "message": message3,
            "signature": BASE64.encode(&signature3),
        });

        let resp = app
            .oneshot(
                Request::post("/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body3.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 409 CONFLICT
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let json = response_json(resp).await;
        assert_eq!(json["error"], "username already taken by another peer");
    }

    #[tokio::test]
    async fn register_duplicate_username_returns_409() {
        let app = setup().await;
        let body = generate_register_body("bob");

        // First registration
        let resp = app
            .clone()
            .oneshot(
                Request::post("/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Second registration with different key but same username
        let body2 = generate_register_body("bob");
        let resp = app
            .oneshot(
                Request::post("/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body2.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let json = response_json(resp).await;
        assert_eq!(json["error"], "username already registered");
    }

    #[tokio::test]
    async fn register_invalid_signature_returns_401() {
        let app = setup().await;

        let keypair = generate_keypair();
        let other_keypair = generate_keypair();
        let public_key = keypair.public().encode_protobuf();
        let message = r#"{"username":"eve"}"#.to_string();
        // Sign with wrong key
        let signature = other_keypair.sign(message.as_bytes()).unwrap();

        let body = serde_json::json!({
            "public_key": BASE64.encode(&public_key),
            "message": message,
            "signature": BASE64.encode(&signature),
        });

        let response = app
            .oneshot(
                Request::post("/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = response_json(response).await;
        assert_eq!(json["error"], "invalid signature");
    }

    #[tokio::test]
    async fn register_non_json_message_returns_400() {
        let app = setup().await;

        let keypair = generate_keypair();
        let public_key = keypair.public().encode_protobuf();
        let message = "not json";
        let signature = keypair.sign(message.as_bytes()).unwrap();

        let body = serde_json::json!({
            "public_key": BASE64.encode(&public_key),
            "message": message,
            "signature": BASE64.encode(&signature),
        });

        let response = app
            .oneshot(
                Request::post("/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = response_json(response).await;
        assert_eq!(
            json["error"],
            "message must be a JSON string containing username"
        );
    }

    #[tokio::test]
    async fn register_empty_username_returns_400() {
        let app = setup().await;

        let keypair = generate_keypair();
        let public_key = keypair.public().encode_protobuf();
        let message = r#"{"username":""}"#.to_string();
        let signature = keypair.sign(message.as_bytes()).unwrap();

        let body = serde_json::json!({
            "public_key": BASE64.encode(&public_key),
            "message": message,
            "signature": BASE64.encode(&signature),
        });

        let response = app
            .oneshot(
                Request::post("/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = response_json(response).await;
        assert_eq!(json["error"], "message.username is required");
    }

    #[tokio::test]
    async fn register_missing_fields_returns_422() {
        let app = setup().await;

        let body = serde_json::json!({ "public_key": "abc" });

        let response = app
            .oneshot(
                Request::post("/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // axum returns 422 when deserialization fails
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    // -- GET /find-by-name --

    #[tokio::test]
    async fn find_by_name_existing_peer() {
        let app = setup().await;
        let body = generate_register_body("charlie");

        // Register first
        let resp = app
            .clone()
            .oneshot(
                Request::post("/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let registered = response_json(resp).await;

        // Find by name
        let resp = app
            .oneshot(
                Request::get("/find-by-name?q=charlie")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let json = response_json(resp).await;
        assert_eq!(json["username"], "charlie");
        assert_eq!(json["peer_id"], registered["peer_id"]);
    }

    #[tokio::test]
    async fn find_by_name_nonexistent_returns_404() {
        let app = setup().await;

        let response = app
            .oneshot(
                Request::get("/find-by-name?q=nobody")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let json = response_json(response).await;
        assert_eq!(json["error"], "peer not found");
    }

    #[tokio::test]
    async fn find_by_name_missing_query_returns_400() {
        let app = setup().await;

        let response = app
            .oneshot(
                Request::get("/find-by-name")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = response_json(response).await;
        assert_eq!(json["error"], "q query parameter is required");
    }

    // -- GET /find-by-id --

    #[tokio::test]
    async fn find_by_id_existing_peer() {
        let app = setup().await;
        let body = generate_register_body("dave");

        // Register first
        let resp = app
            .clone()
            .oneshot(
                Request::post("/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let registered = response_json(resp).await;
        let peer_id = registered["peer_id"].as_str().unwrap();

        // Find by id
        let resp = app
            .oneshot(
                Request::get(&format!("/find-by-id?q={peer_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let json = response_json(resp).await;
        assert_eq!(json["username"], "dave");
        assert_eq!(json["peer_id"], peer_id);
    }

    #[tokio::test]
    async fn find_by_id_nonexistent_returns_404() {
        let app = setup().await;

        let response = app
            .oneshot(
                Request::get("/find-by-id?q=QmNonExistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let json = response_json(response).await;
        assert_eq!(json["error"], "peer not found");
    }

    #[tokio::test]
    async fn find_by_id_missing_query_returns_400() {
        let app = setup().await;

        let response = app
            .oneshot(
                Request::get("/find-by-id").body(Body::empty()).unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = response_json(response).await;
        assert_eq!(json["error"], "q query parameter is required");
    }
}
