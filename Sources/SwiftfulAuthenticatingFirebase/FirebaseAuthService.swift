import Foundation
import SwiftfulAuthenticating
import SignInAppleAsync
@preconcurrency import FirebaseAuth

struct FirebaseAuthService: AuthService {

    func getAuthenticatedUser() -> UserAuthInfo? {
        if let currentUser = Auth.auth().currentUser {
            return UserAuthInfo(user: currentUser)
        }

        return nil
    }

    func addAuthenticatedUserListener() -> AsyncStream<UserAuthInfo?> {
        AsyncStream { continuation in
            _ = Auth.auth().addStateDidChangeListener { _, currentUser in
                if let currentUser {
                    let user = UserAuthInfo(user: currentUser)
                    continuation.yield(user)
                } else {
                    continuation.yield(nil)
                }
            }
        }
    }

    func signIn(option: SignInOption) async throws -> (user: UserAuthInfo, isNewUser: Bool) {
        switch option {
        case .apple:
            return try await authenticateUser_Apple()
        case .anonymous:
            return try await authenticateUser_Anonymous()
        }
    }

    func signOut() throws {
        try Auth.auth().signOut()
    }

    func deleteAccount() async throws {
        guard let user = Auth.auth().currentUser else {
            throw AuthError.userNotFound
        }

        try await user.delete()
    }

}

// MARK: Private

extension FirebaseAuthService {

    private enum AuthError: LocalizedError {
        case noResponse
        case userNotFound

        var errorDescription: String? {
            switch self {
            case .noResponse:
                return "Bad response."
            case .userNotFound:
                return "Current user not found."
            }
        }
    }

    private func authenticateUser_Anonymous() async throws -> (user: UserAuthInfo, isNewUser: Bool) {
        // Sign in to Firebase
        let authDataResult = try await Auth.auth().signInAnonymously()
        
        // Convert Firebase AuthDataResult to local UserAuthInfo
        return authDataResult.asAuthInfo()
    }

    @MainActor
    private func authenticateUser_Apple() async throws -> (user: UserAuthInfo, isNewUser: Bool) {
        let helper = SignInWithAppleHelper()

        // Sign in to Apple
        let response = try await helper.signIn()
        
        // Convert SSO tokens to Firebase credential
        let credential = OAuthProvider.credential(
            providerID: AuthProviderOption.apple.providerId,
            idToken: response.token,
            rawNonce: response.nonce
        )
        
        // Sign in to Firebase
        let result = try await signInOrLink(credential: credential)

        // Convert Firebase AuthDataResult to local UserAuthInfo
        let (user, isNewUser) = result.asAuthInfo(firstName: response.firstName, lastName: response.lastName)
        
        // If new user, update user's Firebase Auth profile
        // Note: possibly change to all sign in, not just new users? what's the overwrite case?
        if isNewUser {
            try await updateUserProfile(
                displayName: user.displayName,
                firstName: user.firstName,
                lastName: user.lastName,
                photoUrl: user.photoURL
            )
        }
        
        return (user, isNewUser)
    }
    
    private func signInOrLink(credential: AuthCredential) async throws -> AuthDataResult {
        // If user is anonymous, attempt to link credential to existing account. On failure, fall-back to signIn to create a new account.
        if let user = Auth.auth().currentUser, user.isAnonymous, let result = try? await user.link(with: credential) {
            return result
        }
        
        return try await Auth.auth().signIn(with: credential)
    }

    private func updateUserProfile(displayName: String?, firstName: String?, lastName: String?, photoUrl: URL?) async throws {
        let request = Auth.auth().currentUser?.createProfileChangeRequest()
        
        var didMakeChanges: Bool = false
        
        // Add display name to Firebase Auth profile
        if let displayName, !displayName.isEmpty {
            request?.displayName = displayName
            didMakeChanges = true
            
        // If no display name, use first or last name instead
        } else if Auth.auth().currentUser?.displayName == nil {
            if let firstName {
                request?.displayName = firstName
                didMakeChanges = true
            } else if let lastName {
                request?.displayName = lastName
                didMakeChanges = true
            }
        }
        
        if let photoUrl {
            request?.photoURL = photoUrl
            didMakeChanges = true
        }
        
        if didMakeChanges {
            try await request?.commitChanges()
        }
    }
}

extension AuthDataResult {

    func asAuthInfo(firstName: String? = nil, lastName: String? = nil) -> (user: UserAuthInfo, isNewUser: Bool) {
        let user = UserAuthInfo(user: user, firstName: firstName, lastName: lastName)
        let isNewUser = additionalUserInfo?.isNewUser ?? true
        return (user, isNewUser)
    }
}


