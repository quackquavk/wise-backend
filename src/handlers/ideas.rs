use actix_web::{post, get, put, delete, HttpMessage, HttpRequest, HttpResponse, web};
use chrono::Utc;
use mongodb::{Database, bson::{doc, oid::ObjectId}};
use validator::Validate;

use crate::{
    middleware::auth::{require_auth, require_admin},
    models::{
        idea::{Idea, CreateIdeaDto},
        user::User,
    },
};

#[post("/ideas")]
pub async fn submit_idea(
    req: HttpRequest,
    db: web::Data<Database>,
    idea_data: web::Json<CreateIdeaDto>,
) -> HttpResponse {
    // Validate input
    if let Err(errors) = idea_data.validate() {
        return HttpResponse::BadRequest().json(errors);
    }

    // Get authenticated user
    let extensions = req.extensions();
    let auth_user = match require_auth(&extensions) {
        Ok(user) => user,
        Err(e) => return HttpResponse::Unauthorized().json(e.to_string()),
    };

    // Get user details from database
    let users_collection = db.collection::<User>("users");
    let user = match users_collection
        .find_one(doc! { "email": &auth_user.email }, None)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return HttpResponse::NotFound().json("User not found"),
        Err(_) => return HttpResponse::InternalServerError().json("Database error"),
    };

    let user_id = user.id.unwrap();

    // Create new idea
    let new_idea = Idea {
        id: None,
        user_id,
        username: user.username,
        email: user.email,
        title: idea_data.title.clone(),
        description: idea_data.description.clone(),
        is_approved: false,
        upvotes: 0,
        upvoted_by: Vec::new(),
        created_at: mongodb::bson::DateTime::from_millis(Utc::now().timestamp_millis()),
        updated_at: mongodb::bson::DateTime::from_millis(Utc::now().timestamp_millis()),
    };

    // Save idea to database
    let ideas_collection = db.collection::<Idea>("ideas");
    match ideas_collection.insert_one(new_idea, None).await {
        Ok(_) => HttpResponse::Created().json("Idea submitted successfully"),
        Err(_) => HttpResponse::InternalServerError().json("Failed to submit idea"),
    }
}

#[get("/ideas")]
pub async fn get_ideas(req: HttpRequest, db: web::Data<Database>) -> HttpResponse {
    // Get current user if authenticated (optional)
    let extensions = req.extensions();
    let current_user = require_auth(&extensions).ok();
    
    let ideas_collection = db.collection::<Idea>("ideas");
    match ideas_collection
        .find(doc! { "is_approved": true }, None)
        .await
    {
        Ok(cursor) => {
            match futures::stream::TryStreamExt::try_collect::<Vec<_>>(cursor).await {
                Ok(ideas) => {
                    // If user is authenticated, include whether they upvoted each idea
                    if let Some(user) = current_user {
                        let user_id = match get_user_id(&db, &user.email).await {
                            Ok(id) => id,
                            Err(_) => return HttpResponse::InternalServerError().json("Failed to get user details"),
                        };

                        let ideas_with_upvote_status: Vec<_> = ideas.into_iter().map(|idea| {
                            let mut idea_json = serde_json::to_value(&idea).unwrap();
                            if let serde_json::Value::Object(ref mut map) = idea_json {
                                map.insert(
                                    "has_upvoted".to_string(),
                                    serde_json::Value::Bool(idea.upvoted_by.contains(&user_id))
                                );
                            }
                            idea_json
                        }).collect();
                        
                        HttpResponse::Ok().json(ideas_with_upvote_status)
                    } else {
                        HttpResponse::Ok().json(ideas)
                    }
                },
                Err(_) => HttpResponse::InternalServerError().json("Failed to fetch ideas"),
            }
        }
        Err(_) => HttpResponse::InternalServerError().json("Failed to fetch ideas"),
    }
}

#[get("/ideas/pending")]
pub async fn get_pending_ideas(req: HttpRequest, db: web::Data<Database>) -> HttpResponse {
    // Verify admin access
    let extensions = req.extensions();
    let _admin = match require_admin(&extensions) {
        Ok(user) => user,
        Err(e) => return HttpResponse::Unauthorized().json(e.to_string()),
    };

    let ideas_collection = db.collection::<Idea>("ideas");
    match ideas_collection
        .find(doc! { "is_approved": false }, None)
        .await
    {
        Ok(cursor) => {
            match futures::stream::TryStreamExt::try_collect::<Vec<_>>(cursor).await {
                Ok(ideas) => HttpResponse::Ok().json(ideas),
                Err(_) => HttpResponse::InternalServerError().json("Failed to fetch ideas"),
            }
        }
        Err(_) => HttpResponse::InternalServerError().json("Failed to fetch ideas"),
    }
}

#[put("/ideas/{id}/approve")]
pub async fn approve_idea(
    req: HttpRequest,
    db: web::Data<Database>,
    id: web::Path<String>,
) -> HttpResponse {
    // Verify admin access
    let extensions = req.extensions();
    if let Err(e) = require_admin(&extensions) {
        return HttpResponse::Unauthorized().json(e.to_string());
    }

    // Convert string ID to ObjectId
    let object_id = match ObjectId::parse_str(id.as_str()) {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().json("Invalid idea ID"),
    };

    let ideas_collection = db.collection::<Idea>("ideas");
    match ideas_collection
        .update_one(
            doc! { "_id": object_id },
            doc! { "$set": { "is_approved": true, "updated_at": mongodb::bson::DateTime::from_millis(Utc::now().timestamp_millis()) } },
            None,
        )
        .await
    {
        Ok(result) => {
            if result.modified_count == 0 {
                HttpResponse::NotFound().json("Idea not found")
            } else {
                HttpResponse::Ok().json("Idea approved successfully")
            }
        }
        Err(_) => HttpResponse::InternalServerError().json("Failed to approve idea"),
    }
}

// Helper function to get user's ObjectId from email
async fn get_user_id(db: &Database, email: &str) -> Result<ObjectId, mongodb::error::Error> {
    let users_collection = db.collection::<User>("users");
    let user = users_collection
        .find_one(doc! { "email": email }, None)
        .await?
        .ok_or_else(|| mongodb::error::Error::custom("User not found"))?;
    
    user.id.ok_or_else(|| mongodb::error::Error::custom("User ID not found"))
}

#[post("/ideas/{id}/upvote")]
pub async fn vote_idea(
    req: HttpRequest,
    db: web::Data<Database>,
    id: web::Path<String>,
) -> HttpResponse {
    // Get authenticated user
    let extensions = req.extensions();
    let auth_user = match require_auth(&extensions) {
        Ok(user) => user,
        Err(e) => return HttpResponse::Unauthorized().json(e.to_string()),
    };

    // Get user's ObjectId
    let user_id = match get_user_id(&db, &auth_user.email).await {
        Ok(id) => id,
        Err(_) => return HttpResponse::InternalServerError().json("Failed to get user details"),
    };

    // Convert string ID to ObjectId
    let idea_id = match ObjectId::parse_str(id.as_str()) {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().json("Invalid idea ID"),
    };

    let ideas_collection = db.collection::<Idea>("ideas");
    
    // Check if user has already upvoted
    let idea = match ideas_collection
        .find_one(doc! { "_id": idea_id }, None)
        .await
    {
        Ok(Some(idea)) => idea,
        Ok(None) => return HttpResponse::NotFound().json("Idea not found"),
        Err(_) => return HttpResponse::InternalServerError().json("Database error"),
    };

    let has_upvoted = idea.upvoted_by.contains(&user_id);
    
    // Toggle upvote
    let update = if has_upvoted {
        doc! {
            "$inc": { "upvotes": -1 },
            "$pull": { "upvoted_by": user_id },
            "$set": { "updated_at": mongodb::bson::DateTime::from_millis(Utc::now().timestamp_millis()) }
        }
    } else {
        doc! {
            "$inc": { "upvotes": 1 },
            "$push": { "upvoted_by": user_id },
            "$set": { "updated_at": mongodb::bson::DateTime::from_millis(Utc::now().timestamp_millis()) }
        }
    };

    match ideas_collection
        .update_one(doc! { "_id": idea_id }, update, None)
        .await
    {
        Ok(result) => {
            if result.modified_count == 0 {
                HttpResponse::NotFound().json("Idea not found")
            } else {
                let message = if has_upvoted {
                    "Upvote removed successfully"
                } else {
                    "Upvote added successfully"
                };
                HttpResponse::Ok().json(message)
            }
        }
        Err(_) => HttpResponse::InternalServerError().json("Failed to update upvote"),
    }
} 