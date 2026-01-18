# API Integration Guide for Swift App

This guide helps you integrate the Biometric Authentication Notes API with your Swift iOS application.

## Quick Start

### 1. Base Configuration

```swift
import Foundation

struct APIConfig {
    static let baseURL = "http://localhost:8080/api"  // Change for production
    static let timeout: TimeInterval = 30.0
}
```

### 2. Network Manager

```swift
class NetworkManager {
    static let shared = NetworkManager()
    private var session: URLSession
    
    private init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = APIConfig.timeout
        self.session = URLSession(configuration: config)
    }
    
    func request<T: Decodable>(
        endpoint: String,
        method: String,
        body: [String: Any]? = nil,
        token: String? = nil,
        completion: @escaping (Result<T, Error>) -> Void
    ) {
        guard let url = URL(string: "\(APIConfig.baseURL)\(endpoint)") else {
            completion(.failure(APIError.invalidURL))
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        if let token = token {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        
        if let body = body {
            request.httpBody = try? JSONSerialization.data(withJSONObject: body)
        }
        
        session.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let data = data else {
                completion(.failure(APIError.noData))
                return
            }
            
            guard let httpResponse = response as? HTTPURLResponse else {
                completion(.failure(APIError.invalidResponse))
                return
            }
            
            if httpResponse.statusCode >= 400 {
                if let errorResponse = try? JSONDecoder().decode(ErrorResponse.self, from: data) {
                    completion(.failure(APIError.serverError(errorResponse.error)))
                } else {
                    completion(.failure(APIError.unknownError))
                }
                return
            }
            
            do {
                let decoded = try JSONDecoder().decode(T.self, from: data)
                completion(.success(decoded))
            } catch {
                completion(.failure(error))
            }
        }.resume()
    }
}

enum APIError: Error, LocalizedError {
    case invalidURL
    case noData
    case invalidResponse
    case serverError(String)
    case unknownError
    
    var errorDescription: String? {
        switch self {
        case .invalidURL: return "Invalid URL"
        case .noData: return "No data received"
        case .invalidResponse: return "Invalid response"
        case .serverError(let message): return message
        case .unknownError: return "Unknown error occurred"
        }
    }
}
```

### 3. Data Models

```swift
// Response Models
struct SignupResponse: Codable {
    let message: String
    let userId: Int
    let username: String
    
    enum CodingKeys: String, CodingKey {
        case message
        case userId = "user_id"
        case username
    }
}

struct LoginResponse: Codable {
    let message: String
    let accessToken: String
    let similarity: Double
    let username: String
    
    enum CodingKeys: String, CodingKey {
        case message
        case accessToken = "access_token"
        case similarity
        case username
    }
}

struct Note: Codable {
    let id: Int
    let title: String
    let content: String
    let createdAt: String
    let updatedAt: String
    
    enum CodingKeys: String, CodingKey {
        case id, title, content
        case createdAt = "created_at"
        case updatedAt = "updated_at"
    }
}

struct NotesResponse: Codable {
    let notes: [Note]
}

struct NoteResponse: Codable {
    let message: String
    let note: Note
}

struct MessageResponse: Codable {
    let message: String
}

struct ErrorResponse: Codable {
    let error: String
}
```

### 4. Biometric Processing

```swift
import LocalAuthentication

class BiometricManager {
    static let shared = BiometricManager()
    
    // Convert biometric template to base64 string
    func encodeVector(_ vector: [Float]) -> String {
        let data = Data(bytes: vector, count: vector.count * MemoryLayout<Float>.size)
        return data.base64EncodedString()
    }
    
    // Decode base64 string to float array
    func decodeVector(_ base64String: String) -> [Float]? {
        guard let data = Data(base64Encoded: base64String) else {
            return nil
        }
        
        let count = data.count / MemoryLayout<Float>.size
        var array = [Float](repeating: 0, count: count)
        _ = array.withUnsafeMutableBytes { data.copyBytes(to: $0) }
        return array
    }
    
    // Authenticate with biometrics and get template
    func authenticateAndGetTemplate(completion: @escaping (Result<[Float], Error>) -> Void) {
        let context = LAContext()
        var error: NSError?
        
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            completion(.failure(error ?? BiometricError.notAvailable))
            return
        }
        
        context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "Authenticate to access your notes"
        ) { success, error in
            if success {
                // Extract biometric template from your biometric feature extraction system
                // This is a placeholder - implement your actual feature extraction
                let template = self.extractBiometricFeatures()
                completion(.success(template))
            } else {
                completion(.failure(error ?? BiometricError.failed))
            }
        }
    }
    
    private func extractBiometricFeatures() -> [Float] {
        // TODO: Implement your actual biometric feature extraction
        // This should return a consistent-length float array representing biometric features
        // For testing, return a random vector:
        return (0..<128).map { _ in Float.random(in: 0...1) }
    }
}

enum BiometricError: Error {
    case notAvailable
    case failed
}
```

### 5. Authentication Service

```swift
class AuthService {
    static let shared = AuthService()
    private let networkManager = NetworkManager.shared
    private let biometricManager = BiometricManager.shared
    
    // Store token securely in Keychain (implement KeychainManager separately)
    private var accessToken: String? {
        get { KeychainManager.shared.get(key: "access_token") }
        set { 
            if let value = newValue {
                KeychainManager.shared.set(value, forKey: "access_token")
            } else {
                KeychainManager.shared.delete(key: "access_token")
            }
        }
    }
    
    func signup(username: String, password: String, completion: @escaping (Result<SignupResponse, Error>) -> Void) {
        biometricManager.authenticateAndGetTemplate { [weak self] result in
            switch result {
            case .success(let template):
                let biometricB64 = self?.biometricManager.encodeVector(template) ?? ""
                
                let body: [String: Any] = [
                    "username": username,
                    "password": password,
                    "biometric_vector": biometricB64
                ]
                
                self?.networkManager.request(
                    endpoint: "/auth/signup",
                    method: "POST",
                    body: body,
                    completion: completion
                )
                
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    func login(username: String, password: String, completion: @escaping (Result<LoginResponse, Error>) -> Void) {
        biometricManager.authenticateAndGetTemplate { [weak self] result in
            switch result {
            case .success(let template):
                let biometricB64 = self?.biometricManager.encodeVector(template) ?? ""
                
                let body: [String: Any] = [
                    "username": username,
                    "password": password,
                    "biometric_vector": biometricB64
                ]
                
                self?.networkManager.request(
                    endpoint: "/auth/login",
                    method: "POST",
                    body: body
                ) { (result: Result<LoginResponse, Error>) in
                    if case .success(let response) = result {
                        self?.accessToken = response.accessToken
                    }
                    completion(result)
                }
                
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    func logout() {
        accessToken = nil
    }
    
    func isAuthenticated() -> Bool {
        return accessToken != nil
    }
    
    func getToken() -> String? {
        return accessToken
    }
}
```

### 6. Notes Service

```swift
class NotesService {
    static let shared = NotesService()
    private let networkManager = NetworkManager.shared
    private let authService = AuthService.shared
    
    func getAllNotes(completion: @escaping (Result<[Note], Error>) -> Void) {
        guard let token = authService.getToken() else {
            completion(.failure(APIError.serverError("Not authenticated")))
            return
        }
        
        networkManager.request(
            endpoint: "/notes",
            method: "GET",
            token: token
        ) { (result: Result<NotesResponse, Error>) in
            switch result {
            case .success(let response):
                completion(.success(response.notes))
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    func getNote(id: Int, completion: @escaping (Result<Note, Error>) -> Void) {
        guard let token = authService.getToken() else {
            completion(.failure(APIError.serverError("Not authenticated")))
            return
        }
        
        networkManager.request(
            endpoint: "/notes/\(id)",
            method: "GET",
            token: token,
            completion: completion
        )
    }
    
    func createNote(title: String, content: String, completion: @escaping (Result<Note, Error>) -> Void) {
        guard let token = authService.getToken() else {
            completion(.failure(APIError.serverError("Not authenticated")))
            return
        }
        
        let body: [String: Any] = [
            "title": title,
            "content": content
        ]
        
        networkManager.request(
            endpoint: "/notes",
            method: "POST",
            body: body,
            token: token
        ) { (result: Result<NoteResponse, Error>) in
            switch result {
            case .success(let response):
                completion(.success(response.note))
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    func updateNote(id: Int, title: String?, content: String?, completion: @escaping (Result<Note, Error>) -> Void) {
        guard let token = authService.getToken() else {
            completion(.failure(APIError.serverError("Not authenticated")))
            return
        }
        
        var body: [String: Any] = [:]
        if let title = title { body["title"] = title }
        if let content = content { body["content"] = content }
        
        networkManager.request(
            endpoint: "/notes/\(id)",
            method: "PUT",
            body: body,
            token: token
        ) { (result: Result<NoteResponse, Error>) in
            switch result {
            case .success(let response):
                completion(.success(response.note))
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    func deleteNote(id: Int, completion: @escaping (Result<Void, Error>) -> Void) {
        guard let token = authService.getToken() else {
            completion(.failure(APIError.serverError("Not authenticated")))
            return
        }
        
        networkManager.request(
            endpoint: "/notes/\(id)",
            method: "DELETE",
            token: token
        ) { (result: Result<MessageResponse, Error>) in
            switch result {
            case .success:
                completion(.success(()))
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
}
```

### 7. Keychain Manager (Secure Token Storage)

```swift
import Security
import Foundation

class KeychainManager {
    static let shared = KeychainManager()
    
    func set(_ value: String, forKey key: String) {
        guard let data = value.data(using: .utf8) else { return }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data
        ]
        
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }
    
    func get(key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let data = result as? Data,
              let value = String(data: data, encoding: .utf8) else {
            return nil
        }
        
        return value
    }
    
    func delete(key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        
        SecItemDelete(query as CFDictionary)
    }
}
```

### 8. Usage Examples

```swift
// Sign up
AuthService.shared.signup(username: "john_doe", password: "SecurePass123!") { result in
    switch result {
    case .success(let response):
        print("User created: \(response.username)")
    case .failure(let error):
        print("Signup failed: \(error.localizedDescription)")
    }
}

// Login
AuthService.shared.login(username: "john_doe", password: "SecurePass123!") { result in
    switch result {
    case .success(let response):
        print("Logged in! Token: \(response.accessToken)")
        print("Biometric similarity: \(response.similarity)")
    case .failure(let error):
        print("Login failed: \(error.localizedDescription)")
    }
}

// Create note
NotesService.shared.createNote(title: "Shopping List", content: "Milk, Eggs, Bread") { result in
    switch result {
    case .success(let note):
        print("Note created with ID: \(note.id)")
    case .failure(let error):
        print("Failed to create note: \(error.localizedDescription)")
    }
}

// Get all notes
NotesService.shared.getAllNotes { result in
    switch result {
    case .success(let notes):
        print("Retrieved \(notes.count) notes")
        for note in notes {
            print("- \(note.title): \(note.content)")
        }
    case .failure(let error):
        print("Failed to retrieve notes: \(error.localizedDescription)")
    }
}

// Update note
NotesService.shared.updateNote(id: 1, title: "Updated Title", content: nil) { result in
    switch result {
    case .success(let note):
        print("Note updated: \(note.title)")
    case .failure(let error):
        print("Failed to update note: \(error.localizedDescription)")
    }
}

// Delete note
NotesService.shared.deleteNote(id: 1) { result in
    switch result {
    case .success:
        print("Note deleted successfully")
    case .failure(let error):
        print("Failed to delete note: \(error.localizedDescription)")
    }
}
```

## Security Best Practices

1. **Always use HTTPS in production** - Never send credentials over HTTP
2. **Store tokens in Keychain** - Never use UserDefaults for sensitive data
3. **Implement certificate pinning** for additional security
4. **Clear tokens on logout** - Properly clean up authentication state
5. **Handle biometric failures gracefully** - Provide fallback authentication
6. **Validate inputs** - Always validate user inputs before sending to API
7. **Implement retry logic** with exponential backoff for network requests
8. **Use App Transport Security** - Configure ATS properly in Info.plist

## Testing

For local development, you may need to configure ATS in `Info.plist`:

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsLocalNetworking</key>
    <true/>
    <key>NSExceptionDomains</key>
    <dict>
        <key>localhost</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <true/>
        </dict>
    </dict>
</dict>
```

**Remove this in production!**
