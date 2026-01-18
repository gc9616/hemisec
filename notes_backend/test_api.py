"""
Test script for the Biometric Authentication Notes API
Run this script to test basic functionality
"""

import requests
import numpy as np
import base64
import json

# Configuration
BASE_URL = "http://localhost:8080/api"
TEST_USERNAME = "test_user"
TEST_PASSWORD = "TestPassword123!"

def create_test_vector():
    """Create a random biometric vector for testing"""
    vector = np.random.rand(128).astype(np.float32)
    return base64.b64encode(vector.tobytes()).decode('utf-8')

def test_signup():
    """Test user signup"""
    print("\n=== Testing Signup ===")
    
    biometric_vector = create_test_vector()
    
    data = {
        "username": TEST_USERNAME,
        "password": TEST_PASSWORD,
        "biometric_vector": biometric_vector
    }
    
    response = requests.post(f"{BASE_URL}/auth/signup", json=data)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    
    return biometric_vector

def test_login(biometric_vector):
    """Test user login"""
    print("\n=== Testing Login ===")
    
    data = {
        "username": TEST_USERNAME,
        "password": TEST_PASSWORD,
        "biometric_vector": biometric_vector
    }
    
    response = requests.post(f"{BASE_URL}/auth/login", json=data)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    
    if response.status_code == 200:
        return response.json()["access_token"]
    return None

def test_create_note(token):
    """Test creating a note"""
    print("\n=== Testing Create Note ===")
    
    headers = {"Authorization": f"Bearer {token}"}
    data = {
        "title": "Test Note",
        "content": "This is a test note created via API"
    }
    
    response = requests.post(f"{BASE_URL}/notes", json=data, headers=headers)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    
    if response.status_code == 201:
        return response.json()["note"]["id"]
    return None

def test_get_notes(token):
    """Test getting all notes"""
    print("\n=== Testing Get All Notes ===")
    
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}/notes", headers=headers)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")

def test_update_note(token, note_id):
    """Test updating a note"""
    print("\n=== Testing Update Note ===")
    
    headers = {"Authorization": f"Bearer {token}"}
    data = {
        "title": "Updated Test Note",
        "content": "This note has been updated"
    }
    
    response = requests.put(f"{BASE_URL}/notes/{note_id}", json=data, headers=headers)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")

def test_delete_note(token, note_id):
    """Test deleting a note"""
    print("\n=== Testing Delete Note ===")
    
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.delete(f"{BASE_URL}/notes/{note_id}", headers=headers)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")

def test_verify_token(token):
    """Test token verification"""
    print("\n=== Testing Token Verification ===")
    
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}/auth/verify", headers=headers)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")

def test_biometric_mismatch(correct_vector):
    """Test login with wrong biometric"""
    print("\n=== Testing Biometric Mismatch ===")
    
    wrong_vector = create_test_vector()  # Different vector
    
    data = {
        "username": TEST_USERNAME,
        "password": TEST_PASSWORD,
        "biometric_vector": wrong_vector
    }
    
    response = requests.post(f"{BASE_URL}/auth/login", json=data)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")

def run_all_tests():
    """Run all tests in sequence"""
    print("=" * 60)
    print("Biometric Authentication Notes API - Test Suite")
    print("=" * 60)
    print(f"\nBase URL: {BASE_URL}")
    print(f"Test User: {TEST_USERNAME}")
    
    try:
        # Test signup
        biometric_vector = test_signup()
        
        # Test login
        token = test_login(biometric_vector)
        
        if not token:
            print("\n❌ Login failed. Cannot continue with other tests.")
            return
        
        # Test token verification
        test_verify_token(token)
        
        # Test creating a note
        note_id = test_create_note(token)
        
        if note_id:
            # Test getting notes
            test_get_notes(token)
            
            # Test updating note
            test_update_note(token, note_id)
            
            # Test getting notes again
            test_get_notes(token)
            
            # Test deleting note
            test_delete_note(token, note_id)
            
            # Verify deletion
            test_get_notes(token)
        
        # Test biometric mismatch
        test_biometric_mismatch(biometric_vector)
        
        print("\n" + "=" * 60)
        print("✅ Test suite completed!")
        print("=" * 60)
        
    except requests.exceptions.ConnectionError:
        print("\n❌ Error: Could not connect to the API server.")
        print("Make sure the Flask server is running on http://localhost:8080")
    except Exception as e:
        print(f"\n❌ Error during testing: {str(e)}")

if __name__ == "__main__":
    run_all_tests()
