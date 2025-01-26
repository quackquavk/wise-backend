use mongodb::bson::{oid::ObjectId, DateTime};
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Idea {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub user_id: ObjectId,
    pub username: String,
    pub email: String,
    pub title: String,
    pub description: String,
    pub is_approved: bool,
    pub upvotes: i32,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateIdeaDto {
    #[validate(length(min = 5, max = 100, message = "Title must be between 5 and 100 characters"))]
    pub title: String,
    #[validate(length(min = 20, max = 1000, message = "Description must be between 20 and 1000 characters"))]
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub enum VoteType {
    Upvote,
    Downvote,
} 