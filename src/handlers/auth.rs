use actix_web::{web, HttpResponse, post, put, get, HttpRequest};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use mongodb::Database;
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken,
    RedirectUrl, Scope, TokenUrl,
};
use serde::{Deserialize, Serialize};
use validator::Validate;
use std::env;
use url::Url;

use crate::{
    models::user::{CreateUserDto, LoginDto, User, UserRole},
    config::get_jwt_secret,
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

fn create_oauth_client() -> BasicClient {
    let google_client_id = ClientId::new(
        env::var("GOOGLE_CLIENT_ID").expect("Missing GOOGLE_CLIENT_ID"),
    );
    let google_client_secret = ClientSecret::new(
        env::var("GOOGLE_CLIENT_SECRET").expect("Missing GOOGLE_CLIENT_SECRET"),
    );
    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
        .expect("Invalid token endpoint URL");
    let redirect_url = RedirectUrl::new(
        env::var("GOOGLE_REDIRECT_URI").expect("Missing GOOGLE_REDIRECT_URI"),
    )
    .expect("Invalid redirect URL");

    BasicClient::new(
        google_client_id,
        Some(google_client_secret),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(redirect_url)
}

#[post("/register")]
pub async fn register(
    db: web::Data<Database>,
    user_data: web::Json<CreateUserDto>,
) -> HttpResponse {
    // Validate input
    if let Err(errors) = user_data.validate() {
        return HttpResponse::BadRequest().json(errors);
    }

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
    db: web::Data<Database>,
    login_data: web::Json<LoginDto>,
) -> HttpResponse {
    // Validate input
    if let Err(errors) = login_data.validate() {
        return HttpResponse::BadRequest().json(errors);
    }

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
    db: web::Data<Database>,
    user_data: web::Json<PromoteToAdminDto>,
) -> HttpResponse {
    let users_collection = db.collection::<User>("users");
    
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
pub async fn google_auth() -> HttpResponse {
    let client = create_oauth_client();
    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url();

    HttpResponse::Found()
        .append_header(("Location", auth_url.to_string()))
        .finish()
}

#[get("/auth/google/callback")]
pub async fn google_auth_callback(
    req: HttpRequest,
    db: web::Data<Database>,
) -> HttpResponse {
    let query_string = req.query_string();
    let frontend_url = env::var("FRONTEND_URL").expect("FRONTEND_URL must be set");
    
    // Parse the query string
    let query_params: Vec<(String, String)> = url::form_urlencoded::parse(query_string.as_bytes())
        .into_owned()
        .collect();
    
    let code = query_params
        .iter()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.clone());
    
    let code = match code {
        Some(code) => code,
        None => {
            return redirect_with_error(&frontend_url, "No authorization code received");
        }
    };

    // Exchange the code for a token
    let client = create_oauth_client();
    let token_result = client
        .exchange_code(oauth2::AuthorizationCode::new(code))
        .request_async(oauth2::reqwest::async_http_client)
        .await;

    let token = match token_result {
        Ok(token) => token,
        Err(e) => {
            return redirect_with_error(&frontend_url, &format!("Token exchange failed: {}", e));
        }
    };

    // Get user info from Google
    let client = reqwest::Client::new();
    let user_info_resp = client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(token.access_token().secret())
        .send()
        .await;

    let google_user = match user_info_resp {
        Ok(response) => {
            match response.json::<GoogleUserInfo>().await {
                Ok(user) => user,
                Err(e) => {
                    return redirect_with_error(&frontend_url, &format!("Failed to parse user info: {}", e));
                }
            }
        }
        Err(e) => {
            return redirect_with_error(&frontend_url, &format!("Failed to get user info: {}", e));
        }
    };

    // Find or create user
    let users_collection = db.collection::<User>("users");
    let user = match users_collection
        .find_one(doc! { "email": &google_user.email }, None)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => {
            // Create new user
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
                Ok(_) => new_user,
                Err(e) => {
                    return redirect_with_error(&frontend_url, &format!("Failed to create user: {}", e));
                }
            }
        }
        Err(e) => {
            return redirect_with_error(&frontend_url, &format!("Database error: {}", e));
        }
    };

    // Generate JWT
    let claims = Claims {
        sub: user.email,
        role: format!("{:?}", user.role),
        exp: (Utc::now().timestamp() + 24 * 3600) as usize, // 24 hours
    };

    let token = match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(get_jwt_secret().as_ref()),
    ) {
        Ok(t) => t,
        Err(e) => {
            return redirect_with_error(&frontend_url, &format!("Failed to create token: {}", e));
        }
    };

    // Redirect to frontend with token
    let mut redirect_url = Url::parse(&frontend_url).unwrap();
    redirect_url.set_query(Some(&format!("token={}", token)));
    
    HttpResponse::Found()
        .append_header(("Location", redirect_url.to_string()))
        .finish()
}

fn redirect_with_error(frontend_url: &str, error: &str) -> HttpResponse {
    let mut url = Url::parse(frontend_url).unwrap();
    url.set_query(Some(&format!("error={}", error)));
    
    HttpResponse::Found()
        .append_header(("Location", url.to_string()))
        .finish()
} 