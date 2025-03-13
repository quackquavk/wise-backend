use actix_web::{web, HttpResponse, post, put, get, HttpRequest};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use mongodb::bson::doc;
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken,
    RedirectUrl, Scope, TokenUrl, TokenResponse
};
use serde::{Deserialize, Serialize};
use validator::Validate;
use std::env;
use url::Url;
use log::{info, warn, error};

use crate::{
    models::user::{CreateUserDto, LoginDto, User, UserRole},
    config::{get_jwt_secret, DatabaseConfig},
};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    role: String,
    exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct GoogleUserInfo {
    email: String,
    name: String,
    picture: Option<String>,
}

#[derive(Serialize)]
struct AuthResponse {
    token: String,
}

#[derive(Deserialize)]
pub struct PromoteToAdminDto {
    pub email: String,
}

fn create_oauth_client(service: &str) -> BasicClient {
    let (client_id, client_secret) = match service {
        "cvai" => (
            ClientId::new(
                env::var("GOOGLE_CLIENT_ID_CVAI").expect("Missing GOOGLE_CLIENT_ID_CVAI"),
            ),
            ClientSecret::new(
                env::var("GOOGLE_CLIENT_SECRET_CVAI").expect("Missing GOOGLE_CLIENT_SECRET_CVAI"),
            )
        ),
        _ => (  // default to wise
            ClientId::new(
                env::var("GOOGLE_CLIENT_ID_WISE").expect("Missing GOOGLE_CLIENT_ID_WISE"),
            ),
            ClientSecret::new(
                env::var("GOOGLE_CLIENT_SECRET_WISE").expect("Missing GOOGLE_CLIENT_SECRET_WISE"),
            )
        )
    };

    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
        .expect("Invalid token endpoint URL");

    // Use service-specific redirect URIs
    let redirect_uri_env = "GOOGLE_REDIRECT_URI_WISE";
    let redirect_url = RedirectUrl::new(
        env::var(redirect_uri_env).expect(&format!("Missing {}", redirect_uri_env)),
    )
    .expect("Invalid redirect URL");

    BasicClient::new(
        client_id,
        Some(client_secret),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(redirect_url)
}

#[post("/register")]
pub async fn register(
    req: HttpRequest,
    db_config: web::Data<DatabaseConfig>,
    user_data: web::Json<CreateUserDto>,
) -> HttpResponse {
    // Validate input
    if let Err(errors) = user_data.validate() {
        return HttpResponse::BadRequest().json(errors);
    }

    // Get service from header
    let service = req
        .headers()
        .get("x-service")
        .and_then(|service_header| service_header.to_str().ok())
        .unwrap_or("wise");  // Default to 'wise' for backward compatibility

    let db = db_config.get_database_for_service(service);

    let users_collection = db.collection::<User>("users");
    
    // Check if email already exists
    if let Ok(Some(_)) = users_collection
        .find_one(
            mongodb::bson::doc! { "email": &user_data.email },
            None,
        )
        .await
    {
        return HttpResponse::BadRequest().json("Email already exists");
    }

    // Check if username already exists
    if let Ok(Some(_)) = users_collection
        .find_one(
            mongodb::bson::doc! { "username": &user_data.username },
            None,
        )
        .await
    {
        return HttpResponse::BadRequest().json("Username already exists");
    }

    // Hash password
    let hashed_password = match hash(user_data.password.as_bytes(), DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().json("Password hashing failed"),
    };

    let new_user = User {
        id: None,
        username: user_data.username.clone(),
        email: user_data.email.clone(),
        password: hashed_password,
        role: UserRole::User,
        created_at: mongodb::bson::DateTime::from_millis(Utc::now().timestamp_millis()),
        updated_at: mongodb::bson::DateTime::from_millis(Utc::now().timestamp_millis()),
    };

    // Insert user
    match users_collection.insert_one(new_user, None).await {
        Ok(_) => HttpResponse::Created().json("User created successfully"),
        Err(_) => HttpResponse::InternalServerError().json("Failed to create user"),
    }
}

#[post("/login")]
pub async fn login(
    req: HttpRequest,
    db_config: web::Data<DatabaseConfig>,
    login_data: web::Json<LoginDto>,
) -> HttpResponse {
    // Validate input
    if let Err(errors) = login_data.validate() {
        return HttpResponse::BadRequest().json(errors);
    }

    // Get service from header
    let service = req
        .headers()
        .get("x-service")
        .and_then(|service_header| service_header.to_str().ok())
        .unwrap_or("wise");  // Default to 'wise' for backward compatibility

    let db = db_config.get_database_for_service(service);

    let users_collection = db.collection::<User>("users");
    
    // Find user
    let user = match users_collection
        .find_one(
            mongodb::bson::doc! { "email": &login_data.email },
            None,
        )
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return HttpResponse::Unauthorized().json("Invalid credentials"),
        Err(_) => return HttpResponse::InternalServerError().json("Database error"),
    };

    // Verify password
    if !verify(&login_data.password, &user.password).unwrap_or(false) {
        return HttpResponse::Unauthorized().json("Invalid credentials");
    }

    // Generate JWT
    let claims = Claims {
        sub: user.email,
        role: format!("{:?}", user.role),
        exp: (Utc::now().timestamp() + 24 * 3600) as usize, // 24 hours
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(get_jwt_secret().as_ref()),
    )
    .unwrap();

    HttpResponse::Ok().json(AuthResponse { token })
}

#[put("/promote-admin")]
pub async fn promote_to_admin(
    db: web::Data<DatabaseConfig>,
    user_data: web::Json<PromoteToAdminDto>,
) -> HttpResponse {
    let users_collection = db.get_database_for_service("wise").collection::<User>("users");
    
    // Update user role to admin
    match users_collection
        .update_one(
            mongodb::bson::doc! { "email": &user_data.email },
            mongodb::bson::doc! { "$set": { "role": "Admin", "updated_at": mongodb::bson::DateTime::from_millis(Utc::now().timestamp_millis()) } },
            None,
        )
        .await
    {
        Ok(result) => {
            if result.modified_count == 0 {
                HttpResponse::NotFound().json("User not found")
            } else {
                HttpResponse::Ok().json("User promoted to admin successfully")
            }
        }
        Err(_) => HttpResponse::InternalServerError().json("Failed to promote user"),
    }
}

#[get("/auth/google")]
pub async fn google_auth(req: HttpRequest) -> HttpResponse {
    // Get service from query parameter first, then fallback to header
    let service = req.query_string()
        .split('&')
        .find(|s| s.starts_with("service="))
        .and_then(|s| s.split('=').nth(1))
        .or_else(|| {
            req.headers()
                .get("x-service")
                .and_then(|service_header| service_header.to_str().ok())
        })
        .unwrap_or("wise");

    // Validate service
    let service = match service {
        "cvai" | "wise" => service,
        _ => "wise"  // default to wise for invalid services
    };

    info!("Starting Google OAuth flow for service: {}", service);
    let client = create_oauth_client(service);
    
    // Generate a random CSRF token
    let csrf_token = CsrfToken::new_random();
    
    // Create a combined state with service and CSRF token
    let combined_state = format!("{}:{}", service, csrf_token.secret());
    info!("Generated combined state: {}", combined_state);
    
    let (auth_url, _) = client
        .authorize_url(|| CsrfToken::new(combined_state.clone()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url();

    info!("Generated Google auth URL with state parameter");
    info!("Redirecting to Google auth URL");

    HttpResponse::Found()
        .append_header(("Location", auth_url.to_string()))
        .finish()
}

#[get("/auth/google/callback")]
pub async fn google_auth_callback(
    req: HttpRequest,
    db_config: web::Data<DatabaseConfig>,
) -> HttpResponse {
    info!("Received callback from Google OAuth");
    let query_string = req.query_string();
    info!("Callback query string: {}", query_string);
    
    // Parse the query string
    let query_params: Vec<(String, String)> = url::form_urlencoded::parse(query_string.as_bytes())
        .into_owned()
        .collect();

    // Extract state which contains service:csrf
    let state = query_params
        .iter()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.clone());
    
    info!("Extracted state value: {:?}", state);

    // Parse state to get service and csrf token
    let (service, csrf) = match state {
        Some(state_str) => {
            let parts: Vec<&str> = state_str.split(':').collect();
            if parts.len() == 2 {
                info!("Successfully parsed service '{}' from state", parts[0]);
                (parts[0].to_string(), parts[1].to_string())
            } else {
                warn!("Invalid state format, defaulting to 'wise' service");
                ("wise".to_string(), state_str)
            }
        }
        None => {
            warn!("No state found, defaulting to 'wise' service");
            ("wise".to_string(), String::new())
        }
    };

    // Get the appropriate frontend URL based on service
    let frontend_url = if service == "cvai" {
        info!("Using CVAI frontend URL");
        env::var("FRONTEND_URL_CVAI").expect("FRONTEND_URL_CVAI must be set")
    } else {
        info!("Using Wise frontend URL");
        env::var("FRONTEND_URL_WISE").expect("FRONTEND_URL_WISE must be set")
    };
    info!("Selected frontend URL: {}", frontend_url);

    info!("Processing OAuth callback for service: {}", service);
    
    let code = query_params
        .iter()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.clone());
    
    let code = match code {
        Some(code) => {
            info!("Successfully extracted authorization code");
            code
        }
        None => {
            error!("No authorization code found in callback");
            return redirect_with_error(&frontend_url, "No authorization code received");
        }
    };

    let db = db_config.get_database_for_service(&service);

    // Exchange the code for a token using the correct client
    info!("Exchanging authorization code for token");
    let client = create_oauth_client(&service);
    let token_result = client
        .exchange_code(oauth2::AuthorizationCode::new(code))
        .request_async(oauth2::reqwest::async_http_client)
        .await;

    let token = match token_result {
        Ok(token) => {
            info!("Successfully exchanged code for token");
            token
        }
        Err(e) => {
            error!("Failed to exchange authorization code for token: {}", e);
            return redirect_with_error(&frontend_url, &format!("Token exchange failed: {}", e));
        }
    };

    // Get user info from Google
    info!("Fetching user info from Google");
    let client = reqwest::Client::new();
    let user_info_resp = client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(token.access_token().secret())
        .send()
        .await;

    let google_user = match user_info_resp {
        Ok(response) => {
            match response.json::<GoogleUserInfo>().await {
                Ok(user) => {
                    info!("Successfully retrieved user info for email: {}", user.email);
                    user
                }
                Err(e) => {
                    error!("Failed to parse user info response: {}", e);
                    return redirect_with_error(&frontend_url, &format!("Failed to parse user info: {}", e));
                }
            }
        }
        Err(e) => {
            error!("Failed to get user info from Google: {}", e);
            return redirect_with_error(&frontend_url, &format!("Failed to get user info: {}", e));
        }
    };

    // Find or create user
    let users_collection = db.collection::<User>("users");
    let user = match users_collection
        .find_one(doc! { "email": &google_user.email }, None)
        .await
    {
        Ok(Some(user)) => {
            user
        }
        Ok(None) => {
            let new_user = User {
                id: None,
                username: google_user.name,
                email: google_user.email.clone(),
                password: "".to_string(), // Not used with OAuth
                role: UserRole::User,
                created_at: mongodb::bson::DateTime::from_millis(Utc::now().timestamp_millis()),
                updated_at: mongodb::bson::DateTime::from_millis(Utc::now().timestamp_millis()),
            };

            match users_collection.insert_one(new_user.clone(), None).await {
                Ok(_) => {
                    new_user
                }
                Err(e) => {
                    error!("Failed to create new user: {}", e);
                    return redirect_with_error(&frontend_url, &format!("Failed to create user: {}", e));
                }
            }
        }
        Err(e) => {
            error!("Database error while looking up user: {}", e);
            return redirect_with_error(&frontend_url, &format!("Database error: {}", e));
        }
    };

    // Generate JWT
    info!("Generating JWT token");
    let claims = Claims {
        sub: user.email.clone(),
        role: format!("{:?}", user.role),
        exp: (Utc::now().timestamp() + 100 * 365 * 24 * 3600) as usize, // 100 years
    };

    let token = match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(get_jwt_secret().as_ref()),
    ) {
        Ok(t) => {
            info!("Successfully generated JWT token");
            t
        }
        Err(e) => {
            error!("Failed to create JWT token: {}", e);
            return redirect_with_error(&frontend_url, &format!("Failed to create token: {}", e));
        }
    };

    info!("Authentication successful for user: {}", user.email);
    // Redirect to frontend with token
    let mut redirect_url = Url::parse(&frontend_url).unwrap();
    redirect_url.set_query(Some(&format!("token={}", token)));
    
    info!("Redirecting to frontend with token");
    HttpResponse::Found()
        .append_header(("Location", redirect_url.to_string()))
        .finish()
}

fn redirect_with_error(frontend_url: &str, error: &str) -> HttpResponse {
    warn!("Redirecting with error: {}", error);
    let mut url = Url::parse(frontend_url).unwrap();
    url.set_query(Some(&format!("error={}", error)));
    
    HttpResponse::Found()
        .append_header(("Location", url.to_string()))
        .finish()
} 