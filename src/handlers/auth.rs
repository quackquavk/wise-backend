use actix_web::{web, HttpResponse, post, put};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use mongodb::Database;
use serde::{Deserialize, Serialize};
use validator::Validate;

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

#[derive(Serialize)]
struct AuthResponse {
    token: String,
}

#[derive(Deserialize)]
pub struct PromoteToAdminDto {
    pub email: String,
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