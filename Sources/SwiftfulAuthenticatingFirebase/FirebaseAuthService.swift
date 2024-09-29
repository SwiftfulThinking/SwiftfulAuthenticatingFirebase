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
        return authDataResult.asAuthInfo
    }

    @MainActor
    private func authenticateUser_Apple() async throws -> (user: UserAuthInfo, isNewUser: Bool) {
        let helper = SignInWithAppleHelper()

        // Sign in to Apple
        let response = try await helper.signIn()
        
        // Sign in to Firebase
        return try await signIn(provider: AuthProviderOption.apple, idToken: response.token, rawNonce: response.nonce)
    }

    private func signIn(provider: AuthProviderOption, idToken: String, rawNonce: String) async throws -> (user: UserAuthInfo, isNewUser: Bool) {
        // Convert SSO tokens to Firebase credential
        let credential = OAuthProvider.credential(providerID: provider.providerId, idToken: idToken, rawNonce: rawNonce)

        // Sign in to Firebase
        let authDataResult = try await Auth.auth().signIn(with: credential)
        
        // Convert Firebase AuthDataResult to local UserAuthInfo
        return authDataResult.asAuthInfo
    }

}

extension AuthDataResult {

    var asAuthInfo: (user: UserAuthInfo, isNewUser: Bool) {
        (UserAuthInfo(user: user), additionalUserInfo?.isNewUser ?? true)
    }
}
