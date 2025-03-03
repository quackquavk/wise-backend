#!/bin/bash

# Base URL for the API
BASE_URL="http://localhost:8000"

# Create an Idea
echo "Creating an Idea..."
CREATE_RESPONSE=$(curl -s -X POST "$BASE_URL/ideas" -H "Content-Type: application/json" -d '{
    "title": "My First Idea",
    "description": "This is a description of my first idea."
}')
echo "Create Response: $CREATE_RESPONSE"

# Get All Ideas
echo "Fetching all Ideas..."
GET_ALL_RESPONSE=$(curl -s -X GET "$BASE_URL/ideas")
echo "Get All Response: $GET_ALL_RESPONSE"

# Extract the ID of the created idea for further testing
IDEA_ID=$(echo $CREATE_RESPONSE | jq -r '.id')  # Assuming the response contains the ID

# Update Idea Status
echo "Updating Idea Status..."
UPDATE_STATUS_RESPONSE=$(curl -s -X PUT "$BASE_URL/ideas/$IDEA_ID/status" -H "Content-Type: application/json" -d '{
    "status": "in_progress"
}')
echo "Update Status Response: $UPDATE_STATUS_RESPONSE"

# Get a Specific Idea
echo "Fetching Idea with ID: $IDEA_ID..."
GET_ID_RESPONSE=$(curl -s -X GET "$BASE_URL/ideas/$IDEA_ID")
echo "Get ID Response: $GET_ID_RESPONSE"

# Upvote an Idea
echo "Upvoting Idea with ID: $IDEA_ID..."
UPVOTE_RESPONSE=$(curl -s -X POST "$BASE_URL/ideas/$IDEA_ID/upvote")
echo "Upvote Response: $UPVOTE_RESPONSE"

# Delete an Idea
echo "Deleting Idea with ID: $IDEA_ID..."
DELETE_RESPONSE=$(curl -s -X DELETE "$BASE_URL/ideas/$IDEA_ID")
echo "Delete Response: $DELETE_RESPONSE" 