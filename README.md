# Wise Backend API Documentation

This is the backend API for the Wise Suggestions platform. It provides endpoints for user authentication, idea submission, and idea management.

## Base URL
```
http://localhost:8080/api
```

## Authentication
Most endpoints require JWT authentication. Include the token in the Authorization header:
```
Authorization: Bearer <your-jwt-token>
```

## Endpoints

### Authentication

#### Register User
```http
POST /register
Content-Type: application/json

{
    "username": "string",     // 3-30 characters
    "email": "string",       // valid email format
    "password": "string"     // minimum 6 characters
}

Response: 201 Created
{
    "message": "User created successfully"
}
```

#### Login
```http
POST /login
Content-Type: application/json

{
    "email": "string",
    "password": "string"
}

Response: 200 OK
{
    "token": "jwt-token-string"
}
```

#### Get Current User
```http
GET /user/me
Authorization: Bearer <token>

Response: 200 OK
{
    "id": "string",
    "username": "string",
    "email": "string",
    "role": "User" | "Admin",
    "created_at": "timestamp",
    "updated_at": "timestamp"
}
```

### Ideas Management

#### Submit New Idea
```http
POST /ideas
Authorization: Bearer <token>
Content-Type: application/json

{
    "title": "string",       // 5-100 characters
    "description": "string"  // 20-1000 characters
}

Response: 201 Created
{
    "message": "Idea submitted successfully"
}
```

#### Get All Approved Ideas
```http
GET /ideas
Authorization: Bearer <token> (optional)

Response: 200 OK
[
    {
        "id": "string",
        "user_id": "string",
        "username": "string",
        "email": "string",
        "title": "string",
        "description": "string",
        "is_approved": true,
        "upvotes": number,
        "has_upvoted": boolean,  // Only included if user is authenticated
        "created_at": "timestamp",
        "updated_at": "timestamp"
    }
]
```

#### Get Pending Ideas (Admin Only)
```http
GET /ideas/pending
Authorization: Bearer <admin-token>

Response: 200 OK
[
    {
        "id": "string",
        "user_id": "string",
        "username": "string",
        "email": "string",
        "title": "string",
        "description": "string",
        "is_approved": false,
        "upvotes": number,
        "created_at": "timestamp",
        "updated_at": "timestamp"
    }
]
```

#### Approve Idea (Admin Only)
```http
PUT /ideas/{idea_id}/approve
Authorization: Bearer <admin-token>

Response: 200 OK
{
    "message": "Idea approved successfully"
}
```

#### Toggle Upvote on an Idea
```http
POST /ideas/{idea_id}/upvote
Authorization: Bearer <token>

Response: 200 OK
{
    "message": "Upvote added successfully" | "Upvote removed successfully"
}
```

## Error Responses

### Common Error Formats
```json
{
    "401": "Authentication required",
    "403": "Admin access required",
    "404": "Resource not found",
    "400": "Validation errors",
    "500": "Internal server error"
}
```

### Validation Errors Example
```json
{
    "email": ["Invalid email format"],
    "password": ["Password must be at least 6 characters long"],
    "title": ["Title must be between 5 and 100 characters"]
}
```

## Notes for Frontend Implementation

1. **Authentication Flow**:
   - After successful login, store the JWT token securely
   - Include the token in all subsequent requests that require authentication
   - Token expires after 24 hours

2. **Admin Features**:
   - Check user.role === "Admin" to show/hide admin features
   - Only admins can view pending ideas and approve them

3. **Idea Submission**:
   - New ideas start with is_approved = false
   - Only approved ideas appear in the public feed
   - Users can toggle their upvotes (add/remove)

4. **Upvote Handling**:
   - The GET /ideas endpoint includes has_upvoted field when user is authenticated
   - Use has_upvoted to show appropriate UI (filled/unfilled upvote button)
   - Upvote endpoint toggles the state (adds or removes upvote)

5. **Error Handling**:
   - Always check for error responses
   - Display appropriate error messages to users
   - Redirect to login if 401 error is received

## Development Setup

1. Backend runs on port 8080
2. CORS is enabled for all origins during development
3. All dates are in ISO format
4. All IDs are MongoDB ObjectIds 