//
//  UserAuthInfo+Firebase.swift
//  SwiftfulAuthenticatingFirebase
//
//  Created by Nick Sarno on 9/28/24.
//
import FirebaseAuth
import SwiftfulAuthenticating

extension UserAuthInfo {

    init(user: User) {
        self.init(
            uid: user.uid,
            email: user.email,
            isAnonymous: user.isAnonymous,
            authProviders: user.providerData.compactMap({ AuthProviderOption(providerId: $0.providerID) }),
            displayName: user.displayName,
            firstName: nil,
            lastName: nil,
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
        }
    }

}
