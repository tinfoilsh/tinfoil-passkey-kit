import AuthenticationServices
import CryptoKit
import Foundation
import Security

/// Configured entry point for passkey ceremonies, CEK protection, and local state.
@MainActor
public final class PasskeyKit: NSObject {
    private let configuration: PasskeyKitConfiguration
    private var authorizationContinuation: CheckedContinuation<ASAuthorization, Error>?

    public init(configuration: PasskeyKitConfiguration) {
        self.configuration = configuration
        super.init()
    }

    /// Creates a PRF-capable passkey and returns its credential ID and PRF output.
    ///
    /// Authenticators may report PRF support without evaluating it during
    /// registration. In that case, the kit immediately performs an assertion.
    public func createPasskey(for user: PasskeyUser) async throws -> PRFPasskeyResult {
        let userID = Data(user.id.utf8)
        guard userID.count <= PasskeyProtocol.maximumUserHandleByteCount else {
            throw PasskeyKitError.userHandleTooLong(userID.count)
        }
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: configuration.rpId
        )
        let request = provider.createCredentialRegistrationRequest(
            challenge: try randomChallenge(),
            name: user.name,
            userID: userID
        )
        request.userVerificationPreference = .required
        request.prf = .inputValues(.saltInput1(configuration.prfSalt))

        let authorization: ASAuthorization
        do {
            authorization = try await performAuthorization(requests: [request])
        } catch {
            throw Self.mapAuthorizationError(error)
        }

        guard let credential = authorization.credential
                as? ASAuthorizationPlatformPublicKeyCredentialRegistration else {
            throw PasskeyKitError.prfNotSupported
        }
        let credentialId = PasskeyCodec.base64URLEncode(credential.credentialID)
        guard let prf = credential.prf, prf.isSupported else {
            throw PasskeyKitError.prfNotSupported
        }
        if let first = prf.first {
            return record(
                PRFPasskeyResult(
                    credentialId: credentialId,
                    prfOutput: first,
                    isPlatformAuthenticator: credential.attachment == .platform
                )
            )
        }
        return try await authenticate(credentialIds: [credentialId])
    }

    /// Authenticates against the supplied credential IDs and evaluates PRF.
    ///
    /// `.immediatelyAvailable` checks only credentials available without
    /// presenting the full cross-device passkey interface.
    public func authenticate(
        credentialIds: [String],
        mode: PasskeyAuthenticationMode = .interactive
    ) async throws -> PRFPasskeyResult {
        guard !credentialIds.isEmpty else {
            throw PasskeyKitError.noCredentialIDs
        }
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: configuration.rpId
        )
        let request = provider.createCredentialAssertionRequest(
            challenge: try randomChallenge()
        )
        request.allowedCredentials = try credentialIds.map {
            ASAuthorizationPlatformPublicKeyCredentialDescriptor(
                credentialID: try PasskeyCodec.base64URLDecode($0)
            )
        }
        request.userVerificationPreference = .required
        request.prf = .inputValues(.saltInput1(configuration.prfSalt))

        let authorization: ASAuthorization
        do {
            authorization = try await performAuthorization(
                requests: [request],
                mode: mode
            )
        } catch {
            throw Self.mapAuthorizationError(error)
        }
        guard let assertion = authorization.credential
                as? ASAuthorizationPlatformPublicKeyCredentialAssertion,
              let prf = assertion.prf else {
            throw PasskeyKitError.prfOutputMissing
        }
        return record(
            PRFPasskeyResult(
                credentialId: PasskeyCodec.base64URLEncode(assertion.credentialID),
                prfOutput: prf.first,
                isPlatformAuthenticator: assertion.attachment == .platform
            )
        )
    }

    public func deriveKeyEncryptionKey(from prfOutput: SymmetricKey) -> SymmetricKey {
        PasskeyCrypto.deriveKeyEncryptionKey(
            from: prfOutput,
            info: configuration.hkdfInfo
        )
    }

    /// Creates a passkey and wraps the supplied 32-byte CEK under its PRF output.
    public func enroll(user: PasskeyUser, cek: Data) async throws -> EnrollmentResult {
        let prfResult = try await createPasskey(for: user)
        let wrapped = try wrapWithPRFResult(prfResult, cek: cek)
        return EnrollmentResult(
            credentialId: prfResult.credentialId,
            wrappedCEK: wrapped,
            prfResult: prfResult
        )
    }

    /// Authenticates against the supplied bundles and unwraps the matching CEK.
    public func unlock(
        _ wrappedCEKs: [WrappedCEK],
        preferredCredentialId: String? = nil,
        mode: PasskeyAuthenticationMode = .interactive
    ) async throws -> UnlockResult {
        guard !wrappedCEKs.isEmpty else {
            throw PasskeyKitError.noMatchingBundle
        }
        let credentialIds = wrappedCEKs.map(\.credentialId)
        let orderedCredentialIds: [String]
        if let preferredCredentialId, credentialIds.contains(preferredCredentialId) {
            orderedCredentialIds = [preferredCredentialId]
                + credentialIds.filter { $0 != preferredCredentialId }
        } else {
            orderedCredentialIds = credentialIds
        }
        let prfResult = try await authenticate(
            credentialIds: orderedCredentialIds,
            mode: mode
        )
        guard let wrapped = wrappedCEKs.first(where: {
            $0.credentialId == prfResult.credentialId
        }) else {
            throw PasskeyKitError.noMatchingBundle
        }
        return UnlockResult(
            credentialId: prfResult.credentialId,
            cek: try unwrapWithPRFResult(prfResult, wrapped: wrapped)
        )
    }

    /// Unwraps a matching bundle with cached PRF output without a new ceremony.
    public func unlockWithCachedPRF(_ wrappedCEKs: [WrappedCEK]) -> UnlockResult? {
        guard let cached = cachedPRFResult(),
              let wrapped = wrappedCEKs.first(where: {
                  $0.credentialId == cached.credentialId
              }),
              let cek = try? unwrapWithPRFResult(cached, wrapped: wrapped) else {
            return nil
        }
        return UnlockResult(credentialId: cached.credentialId, cek: cek)
    }

    public func rewrapWithCachedPRF(_ cek: Data) throws -> WrappedCEK? {
        guard let cached = cachedPRFResult() else { return nil }
        return try wrapWithPRFResult(cached, cek: cek)
    }

    public func wrapWithPRFResult(
        _ result: PRFPasskeyResult,
        cek: Data
    ) throws -> WrappedCEK {
        try PasskeyCrypto.wrapCEK(
            credentialId: result.credentialId,
            kek: deriveKeyEncryptionKey(from: result.prfOutput),
            cek: cek
        )
    }

    public func unwrapWithPRFResult(
        _ result: PRFPasskeyResult,
        wrapped: WrappedCEK
    ) throws -> Data {
        try PasskeyCrypto.unwrapCEK(
            wrapped,
            using: deriveKeyEncryptionKey(from: result.prfOutput)
        )
    }

    public func cachedPRFResult() -> PRFPasskeyResult? {
        configuration.stateStore?.cachedPRFResult()
    }

    public func clearCachedPRFResult() {
        configuration.stateStore?.clearCachedPRFResult()
    }

    public func localCredentialId() -> String? {
        configuration.stateStore?.localCredentialId()
    }

    public func clearLocalState() {
        configuration.stateStore?.clearCachedPRFResult()
        configuration.stateStore?.clearLocalCredentialId()
    }

    private func record(_ result: PRFPasskeyResult) -> PRFPasskeyResult {
        configuration.stateStore?.cachePRFResult(result)
        // Hybrid and security-key credentials are usable for this ceremony but
        // must not make the host think this device owns a platform passkey.
        if result.isPlatformAuthenticator {
            configuration.stateStore?.setLocalCredentialId(result.credentialId)
        }
        return result
    }

    private func randomChallenge() throws -> Data {
        guard configuration.challengeByteCount > 0 else {
            throw PasskeyKitError.invalidChallengeLength(configuration.challengeByteCount)
        }
        var bytes = [UInt8](repeating: 0, count: configuration.challengeByteCount)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw PasskeyKitError.randomGenerationFailed(status)
        }
        return Data(bytes)
    }

    private func performAuthorization(
        requests: [ASAuthorizationRequest],
        mode: PasskeyAuthenticationMode = .interactive
    ) async throws -> ASAuthorization {
        guard authorizationContinuation == nil else {
            throw PasskeyKitError.operationInProgress
        }
        return try await withCheckedThrowingContinuation { continuation in
            authorizationContinuation = continuation
            let controller = ASAuthorizationController(authorizationRequests: requests)
            controller.delegate = self
            switch mode {
            case .interactive:
                controller.performRequests()
            case .immediatelyAvailable:
                controller.performRequests(options: .preferImmediatelyAvailableCredentials)
            }
        }
    }

    private nonisolated static func mapAuthorizationError(_ error: Error) -> PasskeyKitError {
        if let authorizationError = error as? ASAuthorizationError,
           authorizationError.code == .canceled {
            return .userCancelled
        }
        if let passkeyError = error as? PasskeyKitError {
            return passkeyError
        }
        return .authorizationFailed(error)
    }
}

extension PasskeyKit: ASAuthorizationControllerDelegate {
    public func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        authorizationContinuation?.resume(returning: authorization)
        authorizationContinuation = nil
    }

    public func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithError error: Error
    ) {
        authorizationContinuation?.resume(throwing: error)
        authorizationContinuation = nil
    }
}
