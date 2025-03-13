#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color
BLUE='\033[0;34m'
YELLOW='\033[1;33m'

# Base URL
API_URL="http://localhost:8080/api"

# Admin JWT Token
JWT_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwdWthcmtoYW5hbDRAZ21haWwuY29tIiwicm9sZSI6IkFkbWluIiwiZXhwIjo0ODk1NDUyMjkxfQ.fiSXS_5uxgBerV_6GfeLkGiDCn4CvmNSQipplbXf2qs"

# Function to print test results
print_result() {
    local status_code=$1
    local test_name=$2
    local response=$3
    
    if [[ $status_code -ge 200 && $status_code -lt 300 ]]; then
        echo -e "${GREEN}✓ $test_name succeeded (Status: $status_code)${NC}"
    else
        echo -e "${RED}✗ $test_name failed (Status: $status_code)${NC}"
    fi
    echo -e "${YELLOW}Response:${NC}"
    if [ ! -z "$response" ]; then
        if echo "$response" | jq '.' >/dev/null 2>&1; then
            echo "$response" | jq '.'
        else
            echo "$response"
        fi
    else
        echo "No response body"
    fi
    echo "----------------------------------------"
}

echo -e "${BLUE}Starting Idea API endpoint tests...${NC}"
echo "----------------------------------------"

# Test 1: Submit new idea
echo -e "${BLUE}Testing idea submission...${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "${API_URL}/ideas" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${JWT_TOKEN}" \
    -H "x-service: wise" \
    -d '{
        "title": "Test Idea",
        "description": "This is a test idea description"
    }')
STATUS_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')
print_result $STATUS_CODE "Submit Idea" "$BODY"

# Test 2: Get all ideas
echo -e "${BLUE}Testing get all ideas...${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "${API_URL}/ideas" \
    -H "Authorization: Bearer ${JWT_TOKEN}" \
    -H "x-service: wise")
STATUS_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')
print_result $STATUS_CODE "Get All Ideas" "$BODY"

# Store the first idea ID for further tests (extract just the ObjectId string)
IDEA_ID=$(echo "$BODY" | jq -r '.[0]._id.$oid')
if [ -z "$IDEA_ID" ] || [ "$IDEA_ID" = "null" ]; then
    echo -e "${RED}Failed to get idea ID. Exiting...${NC}"
    exit 1
fi
echo -e "${BLUE}Using idea ID: ${IDEA_ID}${NC}"

# Test 3: Get specific idea
echo -e "${BLUE}Testing get specific idea...${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "${API_URL}/ideas/${IDEA_ID}" \
    -H "Authorization: Bearer ${JWT_TOKEN}" \
    -H "x-service: wise")
STATUS_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')
print_result $STATUS_CODE "Get Specific Idea" "$BODY"

# Test 4: Update idea status
echo -e "${BLUE}Testing update idea status...${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT "${API_URL}/ideas/${IDEA_ID}/status" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${JWT_TOKEN}" \
    -H "x-service: wise" \
    -d '{
        "status": "in_progress"
    }')
STATUS_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')
print_result $STATUS_CODE "Update Idea Status" "$BODY"

# Test 5: Upvote idea
echo -e "${BLUE}Testing idea upvote...${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "${API_URL}/ideas/${IDEA_ID}/upvote" \
    -H "Authorization: Bearer ${JWT_TOKEN}" \
    -H "x-service: wise")
STATUS_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')
print_result $STATUS_CODE "Upvote Idea" "$BODY"

# Test 6: Edit idea
echo -e "${BLUE}Testing edit idea...${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT "${API_URL}/ideas/${IDEA_ID}" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${JWT_TOKEN}" \
    -H "x-service: wise" \
    -d '{
        "title": "Updated Test Idea",
        "description": "This is an updated test idea description"
    }')
STATUS_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')
print_result $STATUS_CODE "Edit Idea" "$BODY"

# Test 7: Delete idea (moves to archive)
echo -e "${BLUE}Testing delete idea...${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE "${API_URL}/ideas/${IDEA_ID}" \
    -H "Authorization: Bearer ${JWT_TOKEN}" \
    -H "x-service: wise")
STATUS_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')
print_result $STATUS_CODE "Delete Idea" "$BODY"

# Test 8: Get archived ideas
echo -e "${BLUE}Testing get archived ideas...${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "${API_URL}/ideas/archive" \
    -H "Authorization: Bearer ${JWT_TOKEN}" \
    -H "x-service: wise")
STATUS_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')
print_result $STATUS_CODE "Get Archived Ideas" "$BODY"

# Store the archived idea ID
ARCHIVED_ID=$(echo "$BODY" | jq -r '.[0]._id.$oid')
if [ -z "$ARCHIVED_ID" ] || [ "$ARCHIVED_ID" = "null" ]; then
    echo -e "${RED}Failed to get archived idea ID. Exiting...${NC}"
    exit 1
fi
echo -e "${BLUE}Using archived idea ID: ${ARCHIVED_ID}${NC}"

# Test 9: Restore archived idea
echo -e "${BLUE}Testing restore archived idea...${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "${API_URL}/ideas/archive/${ARCHIVED_ID}/undo" \
    -H "Authorization: Bearer ${JWT_TOKEN}" \
    -H "x-service: wise")
STATUS_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')
print_result $STATUS_CODE "Restore Archived Idea" "$BODY"

# Test 10: Delete from archive permanently
echo -e "${BLUE}Testing delete from archive...${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE "${API_URL}/ideas/archive/${ARCHIVED_ID}" \
    -H "Authorization: Bearer ${JWT_TOKEN}" \
    -H "x-service: wise")
STATUS_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')
print_result $STATUS_CODE "Delete from Archive" "$BODY"

echo -e "${BLUE}All idea endpoint tests completed!${NC}" 