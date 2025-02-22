use mongodb::bson::{oid::ObjectId, DateTime};
use serde::{Deserialize, Serialize};
use validator::Validate;
use std::fmt;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum IdeaStatus {
    Idea,
    InProgress,
    Launched,
    Archived,
}

impl fmt::Display for IdeaStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdeaStatus::Idea => write!(f, "idea"),
            IdeaStatus::InProgress => write!(f, "in_progress"),
            IdeaStatus::Launched => write!(f, "launched"),
            IdeaStatus::Archived => write!(f, "archived"),
        }
    }
}

impl IdeaStatus {
    // Helper method to get status as string for MongoDB
    pub fn as_str(&self) -> &'static str {
        match self {
            IdeaStatus::Idea => "idea",
            IdeaStatus::InProgress => "in_progress",
            IdeaStatus::Launched => "launched",
            IdeaStatus::Archived => "archived",
        }
    }
}

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
    pub status: IdeaStatus,
    pub upvotes: i32,
    pub upvoted_by: Vec<ObjectId>,
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
pub struct UpdateIdeaStatusDto {
    pub status: IdeaStatus,
}

#[derive(Debug, Deserialize)]
pub enum VoteType {
    Upvote,
    Downvote,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeletedIdea {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub original_id: ObjectId,
    pub deleted_by: String,  // Admin's email
    pub deleted_at: DateTime,
    pub idea_data: Idea,  // Store the complete idea data
} 