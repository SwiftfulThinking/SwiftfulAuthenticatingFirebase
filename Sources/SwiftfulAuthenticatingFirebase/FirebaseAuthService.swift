@preconcurrency import Foundation
import Firebase
import SwiftfulAuthenticating
import SignInAppleAsync
import SignInGoogleAsync
@preconcurrency import FirebaseAuth

public struct FirebaseAuthService: AuthService {
    
    public static var clientId: String? {
        FirebaseApp.app()?.options.clientID
    }
    
    public init() {
        
    }

    public func getAuthenticatedUser() -> UserAuthInfo? {
        if let currentUser = Auth.auth().currentUser {
            return UserAuthInfo(user: currentUser)
        }

        return nil
    }

    public func addAuthenticatedUserListener() -> AsyncStream<UserAuthInfo?> {
        AsyncStream { continuation in
            let listener = Auth.auth().addStateDidChangeListener { _, currentUser in
                if let currentUser {
                    let user = UserAuthInfo(user: currentUser)
                    continuation.yield(user)
                    
                    validateAuthToken(user: currentUser)
                } else {
                    continuation.yield(nil)
                }
            }
            
            continuation.onTermination = { @Sendable _ in
                Auth.auth().removeStateDidChangeListener(listener)
            }
        }
    }
    
    // The typical Auth.auth().addStateDidChangeListener and Auth.auth().currentUser rely on cached data in the Keychain.
    // Here, we force a token refresh, which will async hit the server and ensure the user is still authenticated remotely.
    // For example, if we delete the user from the Firebase Authentication console, the cached data wouldn't update automatically.
    private func validateAuthToken(user: User) {
        Task {
            do {
                let token = try await user.getIDToken(forcingRefresh: true)
                print("TOKEN SUCCESS")
            } catch let error as NSError {
                print(error)
                print(error)
                
                if error.code == AuthErrorCode.userTokenExpired.rawValue || error.code == AuthErrorCode.userNotFound.rawValue {
                    print("YUP!")
                    print(error)
                    print(error)

                }
            }
        }
    }

    public func signIn(option: SignInOption) async throws -> (user: UserAuthInfo, isNewUser: Bool) {
        switch option {
        case .apple:
            return try await authenticateUser_Apple()
        case .google(GIDClientID: let GIDClientID):
            return try await authenticateUser_Google(GIDClientID: GIDClientID)
        case .anonymous:
            return try await authenticateUser_Anonymous()
        }
    }

    public func signOut() throws {
        try Auth.auth().signOut()
    }

    public func deleteAccount() async throws {
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
        
        return try await handleConnectToFirebase(
            credential: credential,
            firstName: response.firstName,
            lastName: response.lastName
        )
    }
    
    @MainActor
    private func authenticateUser_Google(GIDClientID: String) async throws -> (user: UserAuthInfo, isNewUser: Bool) {
        let helper = SignInWithGoogleHelper(GIDClientID: GIDClientID)

        // Sign in to Apple
        let response = try await helper.signIn()
        
        // Convert SSO tokens to Firebase credential
        let credential = GoogleAuthProvider.credential(
            withIDToken: response.idToken,
            accessToken: response.accessToken
        )
        
        return try await handleConnectToFirebase(
            credential: credential,
            firstName: response.firstName,
            lastName: response.lastName
        )
    }
    
    private func handleConnectToFirebase(credential: AuthCredential, firstName: String?, lastName: String?) async throws -> (user: UserAuthInfo, isNewUser: Bool) {
        // Sign in to Firebase
        let result = try await signInOrLink(credential: credential)

        // Convert Firebase AuthDataResult to local UserAuthInfo
        let (user, isNewUser) = result.asAuthInfo(firstName: firstName, lastName: lastName)
        
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
        
        // If user is anonymous, attempt to link SSO credential to existing account.
        if let user = Auth.auth().currentUser, user.isAnonymous {
            do {
                // Try to link to existing anonymous account
                return try await user.link(with: credential)
            } catch let error as NSError {
                
                // If link() failed due to providerAlreadyLinked or credentialAlreadyInUse,
                // that means the existing account already has a linked anonymous account.
                // We handle this gracefully by dropping the current anonymous account
                // and switching to the existing account that is connected to the SSO.
                // However, Firebase will throw "duplicate credential" error if we try to use the same credential again
                // So in this edge case, Firebase provides an "UpdatedCredentialKey" to use for the 2nd attempt
                let authError = AuthErrorCode(rawValue: error.code)
                switch authError {
                case .providerAlreadyLinked, .credentialAlreadyInUse:
                    if let secondaryCredential = error.userInfo["FIRAuthErrorUserInfoUpdatedCredentialKey"] as? AuthCredential {
                        return try await Auth.auth().signIn(with: secondaryCredential)
                    }
                default:
                    break
                }
            }
        }
        
        // The default is a regular signIn() without link()
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


