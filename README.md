# Wise Backend API Documentation

This is the backend API for the Wise Suggestions platform. It provides endpoints for user authentication (via Google OAuth2), idea submission, and idea management.

## Base URL
```
http://localhost:8080/api
```

## Authentication

The application uses Google OAuth2 for authentication. Here's how to implement it in your frontend:

### 1. Initiating Google Login

When the user clicks "Continue with Google" or similar button, redirect them to:
```javascript
// Example using vanilla JavaScript
window.location.href = 'http://localhost:8080/api/auth/google';

// Example using React Router
navigate('/api/auth/google');
```

### 2. Handling the OAuth Callback

After Google authentication, users will be redirected to your frontend URL with either:
- Success: `?token=YOUR_JWT_TOKEN`
- Error: `?error=ERROR_MESSAGE`

Example implementation in React:
```javascript
// AuthCallback.jsx
import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

function AuthCallback() {
  const navigate = useNavigate();

  useEffect(() => {
    // Get URL parameters
    const params = new URLSearchParams(window.location.search);
    const token = params.get('token');
    const error = params.get('error');

    if (token) {
      // Store token in localStorage
      localStorage.setItem('auth_token', token);
      // Update auth state (e.g., using context or redux)
      // Redirect to dashboard
      navigate('/dashboard');
    } else if (error) {
      // Handle error
      console.error('Authentication error:', error);
      navigate('/login', { state: { error } });
    }
  }, []);

  return <div>Processing authentication...</div>;
}
```

### 3. Using the JWT Token

For all authenticated requests, include the token in the Authorization header:
```javascript
// Example API call
async function fetchProtectedData() {
  const token = localStorage.getItem('auth_token');
  
  const response = await fetch('http://localhost:8080/api/protected', {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });
  
  if (response.status === 401) {
    // Token expired or invalid
    localStorage.removeItem('auth_token');
    window.location.href = '/login';
    return;
  }
  
  return await response.json();
}
```

### 4. Checking Authentication Status

```javascript
// Example auth check function
function isAuthenticated() {
  const token = localStorage.getItem('auth_token');
  return !!token; // Returns true if token exists
}

// Example protected route component
function ProtectedRoute({ children }) {
  const navigate = useNavigate();
  
  useEffect(() => {
    if (!isAuthenticated()) {
      navigate('/login');
    }
  }, []);
  
  return children;
}
```

## API Endpoints

### Authentication

#### Google OAuth Login
```http
GET /auth/google
```
Initiates the Google OAuth2 flow. Redirects to Google's consent screen.

#### OAuth Callback
```http
GET /auth/google/callback
```
Internal endpoint that handles Google's response. Frontend doesn't need to implement this.

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

## Error Handling

### Common Error Responses
```json
{
    "401": "Authentication required",
    "403": "Admin access required",
    "404": "Resource not found",
    "400": "Validation errors",
    "500": "Internal server error"
}
```

## Frontend Implementation Guide

### 1. Setup Authentication Context (React example)
```javascript
// AuthContext.js
import { createContext, useState, useContext, useEffect } from 'react';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuth();
  }, []);

  async function checkAuth() {
    const token = localStorage.getItem('auth_token');
    if (token) {
      try {
        const response = await fetch('http://localhost:8080/api/user/me', {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
        if (response.ok) {
          const userData = await response.json();
          setUser(userData);
        } else {
          localStorage.removeItem('auth_token');
        }
      } catch (error) {
        console.error('Auth check failed:', error);
      }
    }
    setLoading(false);
  }

  return (
    <AuthContext.Provider value={{ user, loading, checkAuth }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
```

### 2. Login Button Component
```javascript
// LoginButton.js
function LoginButton() {
  return (
    <button
      onClick={() => {
        window.location.href = 'http://localhost:8080/api/auth/google';
      }}
      className="google-login-button"
    >
      Continue with Google
    </button>
  );
}
```

### 3. Protected Route Setup
```javascript
// ProtectedRoute.js
import { Navigate } from 'react-router-dom';
import { useAuth } from './AuthContext';

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!user) {
    return <Navigate to="/login" />;
  }

  return children;
}
```

### 4. Example Usage in App
```javascript
// App.js
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './AuthContext';
import ProtectedRoute from './ProtectedRoute';
import AuthCallback from './AuthCallback';
import Dashboard from './Dashboard';
import Login from './Login';

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/auth/callback" element={<AuthCallback />} />
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
```

## Development Setup

1. Backend runs on port 8080
2. Frontend should run on port 5173 (Vite's default port)
3. Make sure your Google OAuth credentials are properly configured:
   - Authorized JavaScript origins: `http://localhost:5173`
   - Authorized redirect URIs: `http://localhost:8080/api/auth/google/callback`

## Security Notes

1. Always store the JWT token securely (localStorage or httpOnly cookies)
2. Never expose the token in URLs except for the initial OAuth callback
3. Always validate token expiration
4. Clear token on logout or authentication errors
5. Use HTTPS in production 