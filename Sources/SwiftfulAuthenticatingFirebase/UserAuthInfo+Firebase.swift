//
//  UserAuthInfo+Firebase.swift
//  SwiftfulAuthenticatingFirebase
//
//  Created by Nick Sarno on 9/28/24.
//
import FirebaseAuth
import SwiftfulAuthenticating

extension UserAuthInfo {

    /// Initialze from Firebase Auth User
    init(user: User, firstName: String? = nil, lastName: String? = nil) {
        self.init(
            uid: user.uid,
            email: user.email,
            isAnonymous: user.isAnonymous,
            authProviders: user.providerData.compactMap({ AuthProviderOption(providerId: $0.providerID) }),
            displayName: user.displayName,
            firstName: firstName,
            lastName: lastName,
            phoneNumber: user.phoneNumber,
            photoURL: user.photoURL,
            creationDate: user.metadata.creationDate,
            lastSignInDate: user.metadata.lastSignInDate
        )
    }
    
}

extension AuthProviderOption {

    var providerId: AuthProviderID {
        switch self {
        case .google:
            return .google
        case .apple:
            return .apple
        case .email:
            return .email
        case .phone:
            return .phone
        case .facebook:
            return .facebook
        case .gameCenter:
            return .gameCenter
        case .github:
            return .gitHub
        }
    }

}
