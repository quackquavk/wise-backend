use actix_web::{ post, get, put, delete, HttpMessage, HttpRequest, HttpResponse, web };
use chrono::Utc;
use mongodb::{ Database, bson::{ doc, oid::ObjectId } };
use validator::Validate;

use crate::{
    middleware::auth::{ require_auth, require_admin },
    models::{
        idea::{ Idea, CreateIdeaDto, IdeaStatus, UpdateIdeaStatusDto, DeletedIdea },
        user::User,
    },
};

#[post("/ideas")]
pub async fn submit_idea(
    req: HttpRequest,
    db: web::Data<Database>,
    idea_data: web::Json<CreateIdeaDto>
) -> HttpResponse {
    // Validate input
    if let Err(errors) = idea_data.validate() {
        log::error!("Validation error: {:?}", errors);
        return HttpResponse::BadRequest().json(errors);
    }

    // Get authenticated user (any authenticated user can submit ideas)
    let extensions = req.extensions();
    let auth_user = match require_auth(&extensions) {
        Ok(user) => {
            log::info!("User authenticated successfully: {}, role: {}", user.email, user.role);
            user
        }
        Err(e) => {
            log::error!("Authentication failed: {}", e);
            return HttpResponse::Unauthorized().json(e.to_string());
        }
    };

    // Get user details from database
    let users_collection = db.collection::<User>("users");
    let user = match users_collection.find_one(doc! { "email": &auth_user.email }, None).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return HttpResponse::NotFound().json("User not found");
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json("Database error");
        }
    };

    let user_id = user.id.unwrap();

    // Create new idea (now automatically approved since only admins can create)
    let new_idea = Idea {
        id: None,
        user_id,
        username: user.username,
        email: user.email,
        title: idea_data.title.clone(),
        description: idea_data.description.clone(),
        is_approved: true, // Auto-approve since we removed admin-only restriction
        status: IdeaStatus::Idea, // Default status
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

    log::info!("Fetching ideas. User authenticated: {}", current_user.is_some());

    let ideas_collection = db.collection::<Idea>("ideas");
    match
        ideas_collection.find(
            doc! { "is_approved": true },
            mongodb::options::FindOptions
                ::builder()
                .sort(doc! { "created_at": -1 })
                .build()
        ).await
    {
        Ok(cursor) => {
            log::info!("Successfully got cursor from MongoDB");
            match futures::stream::TryStreamExt::try_collect::<Vec<_>>(cursor).await {
                Ok(ideas) => {
                    log::info!("Successfully collected {} ideas", ideas.len());
                    // If user is authenticated, include whether they upvoted each idea
                    if let Some(user) = current_user {
                        log::info!("Adding upvote status for user: {}", user.email);
                        match get_user_id(&db, &user.email).await {
                            Ok(user_id) => {
                                let ideas_with_upvote_status: Vec<_> = ideas
                                    .into_iter()
                                    .map(|idea| {
                                        let mut idea_json = serde_json::to_value(&idea).unwrap();
                                        if let serde_json::Value::Object(ref mut map) = idea_json {
                                            map.insert(
                                                "has_upvoted".to_string(),
                                                serde_json::Value::Bool(
                                                    idea.upvoted_by.contains(&user_id)
                                                )
                                            );
                                        }
                                        idea_json
                                    })
                                    .collect();

                                HttpResponse::Ok().json(ideas_with_upvote_status)
                            }
                            Err(e) => {
                                log::error!("Failed to get user ID: {}", e);
                                HttpResponse::InternalServerError().json(
                                    "Failed to get user details"
                                )
                            }
                        }
                    } else {
                        HttpResponse::Ok().json(ideas)
                    }
                }
                Err(e) => {
                    log::error!("Failed to collect ideas from cursor: {}", e);
                    HttpResponse::InternalServerError().json("Failed to fetch ideas")
                }
            }
        }
        Err(e) => {
            log::error!("Failed to get cursor from MongoDB: {}", e);
            HttpResponse::InternalServerError().json("Failed to fetch ideas")
        }
    }
}

#[get("/ideas/status/{status}")]
pub async fn get_ideas_by_status(
    req: HttpRequest,
    db: web::Data<Database>,
    status: web::Path<String>
) -> HttpResponse {
    // Get current user if authenticated (optional)
    let extensions = req.extensions();
    let current_user = require_auth(&extensions).ok();

    // Parse status
    let status = match status.as_str() {
        "idea" => IdeaStatus::Idea,
        "in_progress" => IdeaStatus::InProgress,
        "launched" => IdeaStatus::Launched,
        _ => {
            return HttpResponse::BadRequest().json("Invalid status");
        }
    };

    let ideas_collection = db.collection::<Idea>("ideas");
    match
        ideas_collection.find(
            doc! { "is_approved": true, "status": status.as_str() },
            mongodb::options::FindOptions
                ::builder()
                .sort(doc! { "created_at": -1 })
                .build()
        ).await
    {
        Ok(cursor) => {
            match futures::stream::TryStreamExt::try_collect::<Vec<_>>(cursor).await {
                Ok(ideas) => {
                    if let Some(user) = current_user {
                        let user_id = match get_user_id(&db, &user.email).await {
                            Ok(id) => id,
                            Err(_) => {
                                return HttpResponse::InternalServerError().json(
                                    "Failed to get user details"
                                );
                            }
                        };

                        let ideas_with_upvote_status: Vec<_> = ideas
                            .into_iter()
                            .map(|idea| {
                                let mut idea_json = serde_json::to_value(&idea).unwrap();
                                if let serde_json::Value::Object(ref mut map) = idea_json {
                                    map.insert(
                                        "has_upvoted".to_string(),
                                        serde_json::Value::Bool(idea.upvoted_by.contains(&user_id))
                                    );
                                }
                                idea_json
                            })
                            .collect();

                        HttpResponse::Ok().json(ideas_with_upvote_status)
                    } else {
                        HttpResponse::Ok().json(ideas)
                    }
                }
                Err(_) => HttpResponse::InternalServerError().json("Failed to fetch ideas"),
            }
        }
        Err(_) => HttpResponse::InternalServerError().json("Failed to fetch ideas"),
    }
}

#[put("/ideas/{id}/status")]
pub async fn update_idea_status(
    req: HttpRequest,
    db: web::Data<Database>,
    id: web::Path<String>,
    status_update: web::Json<UpdateIdeaStatusDto>
) -> HttpResponse {
    // Only admins can update status
    let extensions = req.extensions();
    if let Err(e) = require_admin(&extensions) {
        return HttpResponse::Unauthorized().json(e.to_string());
    }

    // Convert string ID to ObjectId
    let idea_id = match ObjectId::parse_str(id.as_str()) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest().json("Invalid idea ID");
        }
    };

    let ideas_collection = db.collection::<Idea>("ideas");
    match
        ideas_collection.update_one(
            doc! { "_id": idea_id },
            doc! { 
                "$set": { 
                    "status": status_update.status.as_str(),
                    "updated_at": mongodb::bson::DateTime::from_millis(Utc::now().timestamp_millis())
                }
            },
            None
        ).await
    {
        Ok(result) => {
            if result.modified_count == 0 {
                HttpResponse::NotFound().json("Idea not found")
            } else {
                HttpResponse::Ok().json("Idea status updated successfully")
            }
        }
        Err(_) => HttpResponse::InternalServerError().json("Failed to update idea status"),
    }
}

// Helper function to get user's ObjectId from email
async fn get_user_id(db: &Database, email: &str) -> Result<ObjectId, mongodb::error::Error> {
    let users_collection = db.collection::<User>("users");
    let user = users_collection
        .find_one(doc! { "email": email }, None).await?
        .ok_or_else(|| mongodb::error::Error::custom("User not found"))?;

    user.id.ok_or_else(|| mongodb::error::Error::custom("User ID not found"))
}

#[post("/ideas/{id}/upvote")]
pub async fn vote_idea(
    req: HttpRequest,
    db: web::Data<Database>,
    id: web::Path<String>
) -> HttpResponse {
    // Get authenticated user
    let extensions = req.extensions();
    let auth_user = match require_auth(&extensions) {
        Ok(user) => user,
        Err(e) => {
            return HttpResponse::Unauthorized().json(e.to_string());
        }
    };

    // Get user's ObjectId
    let user_id = match get_user_id(&db, &auth_user.email).await {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::InternalServerError().json("Failed to get user details");
        }
    };

    // Convert string ID to ObjectId
    let idea_id = match ObjectId::parse_str(id.as_str()) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest().json("Invalid idea ID");
        }
    };

    let ideas_collection = db.collection::<Idea>("ideas");

    // Check if user has already upvoted
    let idea = match ideas_collection.find_one(doc! { "_id": idea_id }, None).await {
        Ok(Some(idea)) => idea,
        Ok(None) => {
            return HttpResponse::NotFound().json("Idea not found");
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json("Database error");
        }
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

    // Update the idea
    match ideas_collection.update_one(doc! { "_id": idea_id }, update, None).await {
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

#[get("/ideas/{id}")]
pub async fn get_idea(
    req: HttpRequest,
    db: web::Data<Database>,
    id: web::Path<String>
) -> HttpResponse {
    // Get current user if authenticated (optional)
    let extensions = req.extensions();
    let current_user = require_auth(&extensions).ok();

    // Convert string ID to ObjectId
    let idea_id = match ObjectId::parse_str(id.as_str()) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest().json("Invalid idea ID");
        }
    };

    let ideas_collection = db.collection::<Idea>("ideas");
    match ideas_collection.find_one(doc! { "_id": idea_id }, None).await {
        Ok(Some(idea)) => {
            // If user is authenticated, include whether they upvoted this idea
            if let Some(user) = current_user {
                match get_user_id(&db, &user.email).await {
                    Ok(user_id) => {
                        let mut idea_json = serde_json::to_value(&idea).unwrap();
                        if let serde_json::Value::Object(ref mut map) = idea_json {
                            map.insert(
                                "has_upvoted".to_string(),
                                serde_json::Value::Bool(idea.upvoted_by.contains(&user_id))
                            );
                        }
                        HttpResponse::Ok().json(idea_json)
                    }
                    Err(_) =>
                        HttpResponse::InternalServerError().json("Failed to get user details"),
                }
            } else {
                HttpResponse::Ok().json(idea)
            }
        }
        Ok(None) => HttpResponse::NotFound().json("Idea not found"),
        Err(_) => HttpResponse::InternalServerError().json("Failed to fetch idea"),
    }
}

#[delete("/ideas/{id}")]
pub async fn delete_idea(
    req: HttpRequest,
    db: web::Data<Database>,
    id: web::Path<String>
) -> HttpResponse {
    // Only admins can delete ideas
    let extensions = req.extensions();
    let admin = match require_admin(&extensions) {
        Ok(user) => user,
        Err(e) => {
            return HttpResponse::Unauthorized().json(e.to_string());
        }
    };

    // Convert string ID to ObjectId
    let idea_id = match ObjectId::parse_str(id.as_str()) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest().json("Invalid idea ID");
        }
    };

    let ideas_collection = db.collection::<Idea>("ideas");
    let deleted_ideas_collection = db.collection::<DeletedIdea>("deleted_ideas");

    // First, get the idea to be deleted
    let idea = match ideas_collection.find_one(doc! { "_id": idea_id }, None).await {
        Ok(Some(idea)) => idea,
        Ok(None) => {
            return HttpResponse::NotFound().json("Idea not found");
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json("Database error");
        }
    };

    // Create deleted idea record
    let deleted_idea = DeletedIdea {
        id: None,
        original_id: idea_id,
        deleted_by: admin.email.clone(),
        deleted_at: mongodb::bson::DateTime::from_millis(Utc::now().timestamp_millis()),
        idea_data: idea.clone(),
    };

    // Insert into deleted_ideas collection
    match deleted_ideas_collection.insert_one(deleted_idea, None).await {
        Ok(_) => {
            // Now delete from main ideas collection
            match ideas_collection.delete_one(doc! { "_id": idea_id }, None).await {
                Ok(result) => {
                    if result.deleted_count == 0 {
                        HttpResponse::NotFound().json("Idea not found")
                    } else {
                        HttpResponse::Ok().json("Idea deleted successfully")
                    }
                }
                Err(_) => HttpResponse::InternalServerError().json("Failed to delete idea"),
            }
        }
        Err(_) => HttpResponse::InternalServerError().json("Failed to archive deleted idea"),
    }
}
