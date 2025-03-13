use actix_web::{get, HttpMessage, HttpRequest, HttpResponse};
use mongodb::bson::doc;
use crate::middleware::auth::{require_auth, require_admin};
use crate::models::user::User;
use crate::config::DatabaseConfig;

#[get("/protected")]
pub async fn protected_route(req: HttpRequest) -> HttpResponse {
    // Get the extensions from the request
    let extensions = req.extensions();
    
    // This will return error if user is not authenticated
    let user = match require_auth(&extensions) {
        Ok(user) => user,
        Err(e) => return HttpResponse::Unauthorized().json(e.to_string()),
    };

    HttpResponse::Ok().json(format!("Hello, {}!", user.email))
}

#[get("/admin")]
pub async fn admin_route(req: HttpRequest) -> HttpResponse {
    // Get the extensions from the request
    let extensions = req.extensions();
    
    // This will return error if user is not an admin
    let admin = match require_admin(&extensions) {
        Ok(user) => user,
        Err(e) => return HttpResponse::Unauthorized().json(e.to_string()),
    };

    HttpResponse::Ok().json(format!("Hello admin: {}", admin.email))
}

#[get("/user/me")]
pub async fn get_current_user(
    req: HttpRequest, 
    db_config: actix_web::web::Data<DatabaseConfig>
) -> HttpResponse {
    // Get the extensions from the request
    let extensions = req.extensions();
    
    // This will return error if user is not authenticated
    let auth_user = match require_auth(&extensions) {
        Ok(user) => user,
        Err(e) => return HttpResponse::Unauthorized().json(e.to_string()),
    };

    // Get service from header
    let service = req
        .headers()
        .get("x-service")
        .and_then(|service_header| service_header.to_str().ok())
        .unwrap_or("wise");

    let db = db_config.get_database_for_service(service);

    // Get user details from database
    let users_collection = db.collection::<User>("users");
    match users_collection
        .find_one(doc! { "email": &auth_user.email }, None)
        .await
    {
        Ok(Some(user)) => {
            // Create a response that excludes sensitive information
            let user_response = serde_json::json!({
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "created_at": user.created_at,
                "updated_at": user.updated_at
            });
            HttpResponse::Ok().json(user_response)
        }
        Ok(None) => HttpResponse::NotFound().json("User not found"),
        Err(_) => HttpResponse::InternalServerError().json("Failed to fetch user details"),
    }
} 