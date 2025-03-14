use actix_web::{ post, get, put, delete, HttpMessage, HttpRequest, HttpResponse, web };
use chrono::Utc;
use mongodb::{ Database, bson::{ doc, oid::ObjectId } };
use validator::Validate;

use crate::{
    middleware::auth::{ require_auth, require_admin },
    models::{
        idea::{ Idea, CreateIdeaDto, IdeaStatus, UpdateIdeaStatusDto, DeletedIdea, UpdateIdeaDto },
        user::User,
    },
    config::DatabaseConfig,
};

#[post("/ideas")]
pub async fn submit_idea(
    req: HttpRequest,
    db_config: web::Data<DatabaseConfig>,
    idea_data: web::Json<CreateIdeaDto>
) -> HttpResponse {
    if let Err(errors) = idea_data.validate() {
        return HttpResponse::BadRequest().json(errors);
    }

    // Get service from header
    let service = req
        .headers()
        .get("x-service")
        .and_then(|service_header| service_header.to_str().ok())
        .unwrap_or("wise");  // Default to 'wise' for backward compatibility

    let db = db_config.get_database_for_service(service);

    let extensions = req.extensions();
    let auth_user = match require_auth(&extensions) {
        Ok(user) => user,
        Err(e) => {
            return HttpResponse::Unauthorized().json(e.to_string());
        }
    };

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

    let new_idea = Idea {
        id: None,
        user_id,
        username: user.username,
        email: user.email,
        title: idea_data.title.clone(),
        description: idea_data.description.clone(),
        is_approved: true,
        status: IdeaStatus::Launched,
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
pub async fn get_ideas(req: HttpRequest, db_config: web::Data<DatabaseConfig>) -> HttpResponse {
    // Get service from header
    let service = req
        .headers()
        .get("x-service")
        .and_then(|service_header| service_header.to_str().ok())
        .unwrap_or("wise");

    let db = db_config.get_database_for_service(service);

    // Get current user if authenticated (optional)
    let extensions = req.extensions();
    let current_user = require_auth(&extensions).ok();

    log::info!("Fetching ideas for service: {}. User authenticated: {}", service, current_user.is_some());

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
                    log::info!("Found {} ideas", ideas.len());
                    // If user is authenticated, include whether they upvoted each idea
                    if let Some(user) = current_user {
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

// #[get("/ideas/status/{status}")]
// pub async fn get_ideas_by_status(
//     req: HttpRequest,
//     db: web::Data<Database>,
//     status: web::Path<String>
// ) -> HttpResponse {
//     // Get current user if authenticated (optional)
//     let extensions = req.extensions();
//     let current_user = require_auth(&extensions).ok();

//     // Parse status
//     let status = match status.as_str() {
//         "idea" => IdeaStatus::Idea,
//         "in_progress" => IdeaStatus::InProgress,
//         "launched" => IdeaStatus::Launched,
//         _ => {
//             return HttpResponse::BadRequest().json("Invalid status");
//         }
//     };

//     let ideas_collection = db.collection::<Idea>("ideas");
//     match
//         ideas_collection.find(
//             doc! { "is_approved": true, "status": status.as_str() },
//             mongodb::options::FindOptions
//                 ::builder()
//                 .sort(doc! { "created_at": -1 })
//                 .build()
//         ).await
//     {
//         Ok(cursor) => {
//             match futures::stream::TryStreamExt::try_collect::<Vec<_>>(cursor).await {
//                 Ok(ideas) => {
//                     if let Some(user) = current_user {
//                         let user_id = match get_user_id(&db, &user.email).await {
//                             Ok(id) => id,
//                             Err(_) => {
//                                 return HttpResponse::InternalServerError().json(
//                                     "Failed to get user details"
//                                 );
//                             }
//                         };

//                         let ideas_with_upvote_status: Vec<_> = ideas
//                             .into_iter()
//                             .map(|idea| {
//                                 let mut idea_json = serde_json::to_value(&idea).unwrap();
//                                 if let serde_json::Value::Object(ref mut map) = idea_json {
//                                     map.insert(
//                                         "has_upvoted".to_string(),
//                                         serde_json::Value::Bool(idea.upvoted_by.contains(&user_id))
//                                     );
//                                 }
//                                 idea_json
//                             })
//                             .collect();

//                         HttpResponse::Ok().json(ideas_with_upvote_status)
//                     } else {
//                         HttpResponse::Ok().json(ideas)
//                     }
//                 }
//                 Err(_) => HttpResponse::InternalServerError().json("Failed to fetch ideas"),
//             }
//         }
//         Err(_) => HttpResponse::InternalServerError().json("Failed to fetch ideas"),
//     }
// }

#[put("/ideas/{id}/status")]
pub async fn update_idea_status(
    req: HttpRequest,
    db_config: web::Data<DatabaseConfig>,
    id: web::Path<String>,
    status_update: web::Json<UpdateIdeaStatusDto>
) -> HttpResponse {
    // Only admins can update status
    let extensions = req.extensions();
    if let Err(e) = require_admin(&extensions) {
        return HttpResponse::Unauthorized().json(e.to_string());
    }

    // Get service from header
    let service = req
        .headers()
        .get("x-service")
        .and_then(|service_header| service_header.to_str().ok())
        .unwrap_or("wise");

    let db = db_config.get_database_for_service(service);

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
    db_config: web::Data<DatabaseConfig>,
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

    // Get service from header
    let service = req
        .headers()
        .get("x-service")
        .and_then(|service_header| service_header.to_str().ok())
        .unwrap_or("wise");

    let db = db_config.get_database_for_service(service);

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
    db_config: web::Data<DatabaseConfig>,
    id: web::Path<String>
) -> HttpResponse {
    // Get current user if authenticated (optional)
    let extensions = req.extensions();
    let current_user = require_auth(&extensions).ok();

    // Get service from header
    let service = req
        .headers()
        .get("x-service")
        .and_then(|service_header| service_header.to_str().ok())
        .unwrap_or("wise");

    let db = db_config.get_database_for_service(service);

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
    db_config: web::Data<DatabaseConfig>,
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

    // Get service from header
    let service = req
        .headers()
        .get("x-service")
        .and_then(|service_header| service_header.to_str().ok())
        .unwrap_or("wise");

    let db = db_config.get_database_for_service(service);

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
        Ok(Some(mut idea)) => {
            idea.status = IdeaStatus::Archived;
            idea
        },
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

#[get("/ideas/archive")]
pub async fn get_archive(req: HttpRequest, db_config: web::Data<DatabaseConfig>) -> HttpResponse {
    // Only admins can access the archive
    let extensions = req.extensions();
    let _admin = match require_admin(&extensions) {
        Ok(user) => user,
        Err(e) => {
            return HttpResponse::Unauthorized().json(e.to_string());
        }
    };

    // Get service from header
    let service = req
        .headers()
        .get("x-service")
        .and_then(|service_header| service_header.to_str().ok())
        .unwrap_or("wise");

    let db = db_config.get_database_for_service(service);

    let archive_collection = db.collection::<DeletedIdea>("deleted_ideas");
    
    // Get all deleted ideas, sorted by deletion date (newest first)
    match archive_collection
        .find(
            doc! {},
            mongodb::options::FindOptions::builder()
                .sort(doc! { "deleted_at": -1 })
                .build()
        )
        .await
    {
        Ok(cursor) => {
            match futures::stream::TryStreamExt::try_collect::<Vec<_>>(cursor).await {
                Ok(ideas) => {
                    let idea_data: Vec<_> = ideas.into_iter().map(|idea| {
                        let mut idea_data = idea.idea_data;
                        idea_data.id = idea.id; // Add the idea._id as db_id
                        idea_data
                    }).collect();
                    
                    HttpResponse::Ok().json(idea_data)
                }
                Err(e) => {
                    log::error!("Failed to collect archived ideas: {}", e);
                    HttpResponse::InternalServerError().json("Failed to fetch archived ideas")
                }
            }
        }
        Err(e) => {
            log::error!("Failed to query archive collection: {}", e);
            HttpResponse::InternalServerError().json("Failed to fetch archived ideas")
        }
    }
}

#[delete("/ideas/archive/{id}")]
pub async fn delete_from_archive(
    req: HttpRequest, 
    db_config: web::Data<DatabaseConfig>, 
    id: web::Path<String>
) -> HttpResponse {
    let extensions = req.extensions();
    let _admin = match require_admin(&extensions) {
        Ok(user) => user,
        Err(e) => {
            return HttpResponse::Unauthorized().json(e.to_string());
        }
    };

    // Get service from header
    let service = req
        .headers()
        .get("x-service")
        .and_then(|service_header| service_header.to_str().ok())
        .unwrap_or("wise");

    let db = db_config.get_database_for_service(service);

    let archive_collection = db.collection::<DeletedIdea>("deleted_ideas");

    // Convert string ID to ObjectId
    let idea_id = match ObjectId::parse_str(id.as_str()) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest().json("Invalid archive ID");
        }
    };

    // Delete from archive collection
    match archive_collection.delete_one(doc! { "_id": idea_id }, None).await {
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

/// Restores an archived idea back to the main ideas collection.
///
/// # Parameters
/// - `req`: The HTTP request containing the context and user information.
/// - `db`: The database connection containing the ideas and archived ideas collections.
/// - `id`: The path parameter containing the ID of the archived idea to restore.
///
/// # Returns
/// - `HttpResponse`: A response indicating the success or failure of the restoration process.
#[post("/ideas/archive/{id}/undo")]
pub async fn undo_archive(
    req: HttpRequest, 
    db_config: web::Data<DatabaseConfig>, 
    id: web::Path<String>
) -> HttpResponse {
    let extensions = req.extensions();
    let _admin = match require_admin(&extensions) {
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

    let archive_collection = db.collection::<DeletedIdea>("deleted_ideas");

    // Convert string ID to ObjectId
    let idea_id = match ObjectId::parse_str(id.as_str()) {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().json("Invalid archive ID"),
    };

    // Get the idea from the archive
    let deleted_idea = match archive_collection.find_one(doc! { "_id": idea_id }, None).await {
        Ok(Some(idea)) => idea,
        Ok(None) => return HttpResponse::NotFound().json("Idea not found in archive"),
        Err(_) => return HttpResponse::InternalServerError().json("Database error"),
    };

    // Insert the idea back into the main ideas collection
    let ideas_collection = db.collection::<Idea>("ideas");
    if let Err(_) = ideas_collection.insert_one(deleted_idea.idea_data.clone(), None).await {
        return HttpResponse::InternalServerError().json("Failed to restore idea");
    }

    // Set the status of the idea after restoration
    let update_result = ideas_collection.update_one(
        doc! { "_id": &deleted_idea.idea_data.id },
        doc! { "$set": { "status": IdeaStatus::Idea.as_str(), "updated_at": mongodb::bson::DateTime::from_millis(Utc::now().timestamp_millis()) } },
        None,
    ).await;

    match update_result {
        Ok(_) => {
            // Delete from archive collection
            if let Err(_) = archive_collection.delete_one(doc! { "_id": idea_id }, None).await {
                return HttpResponse::InternalServerError().json("Failed to delete idea from archive");
            }
            HttpResponse::Ok().json("Idea restored successfully")
        }
        Err(_) => HttpResponse::InternalServerError().json("Failed to update idea status"),
    }
}

#[put("/ideas/{id}")]
pub async fn edit_idea(
    req: HttpRequest, 
    db_config: web::Data<DatabaseConfig>, 
    id: web::Path<String>, 
    idea_data: web::Json<UpdateIdeaDto>
) -> HttpResponse {
    let extensions = req.extensions();
    let _admin = match require_admin(&extensions) {
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

    let ideas_collection = db.collection::<Idea>("ideas");
    let idea_id = match ObjectId::parse_str(id.as_str()) {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().json("Invalid idea ID"),
    };

    let update_result = ideas_collection.update_one(
        doc! { "_id": idea_id },
        doc! { "$set": { "title": &idea_data.title, "description": &idea_data.description, "updated_at": mongodb::bson::DateTime::from_millis(Utc::now().timestamp_millis()) } },
        None,
    ).await;

    match update_result {
        Ok(_) => HttpResponse::Ok().json("Idea updated successfully"),
        Err(_) => HttpResponse::InternalServerError().json("Failed to update idea"),
    }
}