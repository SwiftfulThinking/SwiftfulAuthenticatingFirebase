# Firebase Authentication for SwiftfulAuthenticating ✅

Add FirebaseAuth support to a Swift application through SwiftfulAuthenticating framework.

See documentation in the parent repo: https://github.com/SwiftfulThinking/SwiftfulAuthenticating

## Example configuration:
```swift
// Example
#if DEBUG
let authManager = AuthManager(service: MockAuthService(user: nil))
#else
let authManager = AuthManager(service: FirebaseAuthService())
#endif
```

## Example actions:

```swift
let uid = authManager.auth.uid
let uid = try authManager.getAuthId()
try await authManager.signInAnonymous()
try await authManager.signInApple()
try await authManager.signInGoogle(GIDClientID: String)
try await authManager.signOut()
try await authManager.deleteAccount()
```

## Sign In With Apple

<details>
<summary> Details (Click to expand) </summary>
<br>

Firebase docs: https://firebase.google.com/docs/auth/ios/apple

### 1. Enable Apple as a Sign-In Method in Firebase Authentication console.
* Firebase Console -> Authentication -> Sign-in method -> Add new provider

### 2. Follow remaining steps on parent repo docs
Parent repo: https://github.com/SwiftfulThinking/SwiftfulFirebaseAuth/edit/main/README.md

</details>


## Sign In With Google

<details>
<summary> Details (Click to expand) </summary>
<br>

Firebase docs: https://firebase.google.com/docs/auth/ios/google-signin

### 1. Enable Google as a Sign-In Method in Firebase Authentication console.
* Firebase Console -> Authentication -> Sign-in method -> Add new provider

### 2. Follow remaining steps on parent repo docs
Parent repo: https://github.com/SwiftfulThinking/SwiftfulFirebaseAuth/edit/main/README.md

</details>

