# SwiftfulAuthenticatingFirebase

Add Firebase Auth support to a Swift application through the [SwiftfulAuthenticating](https://github.com/SwiftfulThinking/SwiftfulAuthenticating) framework.

## Setup

<details>
<summary> Details (Click to expand) </summary>
<br>

Add SwiftfulAuthenticatingFirebase to your project.

```
https://github.com/SwiftfulThinking/SwiftfulAuthenticatingFirebase.git
```

Import the package.

```swift
import SwiftfulAuthenticatingFirebase
```

Configure `AuthManager` with `FirebaseAuthService`:

```swift
#if DEBUG
let authManager = AuthManager(service: MockAuthService(user: nil), logger: logManager)
#else
let authManager = AuthManager(service: FirebaseAuthService(), logger: logManager)
#endif
```

</details>

## Example Actions

```swift
let uid = authManager.auth?.uid
let uid = try authManager.getAuthId()
try await authManager.signInAnonymously()
try await authManager.signInApple()
try await authManager.signInGoogle(GIDClientID: clientId)
try authManager.signOut()
try await authManager.deleteAccount()
```

## Sign In With Apple

<details>
<summary> Details (Click to expand) </summary>
<br>

Firebase docs: https://firebase.google.com/docs/auth/ios/apple

### 1. Enable Apple as a Sign-In Method in Firebase Authentication console

- Firebase Console -> Authentication -> Sign-in method -> Add new provider

### 2. Follow remaining steps on parent repo docs

Parent repo: https://github.com/SwiftfulThinking/SwiftfulAuthenticating

</details>

## Sign In With Google

<details>
<summary> Details (Click to expand) </summary>
<br>

Firebase docs: https://firebase.google.com/docs/auth/ios/google-signin

### 1. Enable Google as a Sign-In Method in Firebase Authentication console

- Firebase Console -> Authentication -> Sign-in method -> Add new provider

### 2. Follow remaining steps on parent repo docs

Parent repo: https://github.com/SwiftfulThinking/SwiftfulAuthenticating

</details>

## Claude Code

This package is used via [SwiftfulAuthenticating](https://github.com/SwiftfulThinking/SwiftfulAuthenticating). See the parent package's `.claude/swiftful-authenticating-rules.md` for usage guidelines and integration advice for projects using [Claude Code](https://claude.ai/claude-code).

## Platform Support

- **iOS 17.0+**
- **macOS 14.0+**

## License

SwiftfulAuthenticatingFirebase is available under the MIT license.
