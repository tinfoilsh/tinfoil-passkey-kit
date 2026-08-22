import AuthenticationServices
import CryptoKit
import Foundation
import Security

struct CeremonyResult: Sendable {
    let credentialId: String
    let prfOutput: Data
    let isPlatformAuthenticator: Bool
}

enum CeremonyRequest: Sendable {
    case create(
        profile: PasskeyKeyProfile,
        relyingPartyName: String,
        user: PasskeyUser
    )
    case recover(
        profile: PasskeyKeyProfile,
        credentialIds: [String],
        interaction: PasskeyInteraction
    )
}

@MainActor
protocol CeremonyControlling: AnyObject {
    func cancel()
}

@MainActor
protocol CeremonyDriving: AnyObject {
    func capability(operation: PasskeyOperation) async -> PasskeyCapability
    func start(
        request: CeremonyRequest,
        completion: @escaping @MainActor (Result<CeremonyResult, Error>) -> Void
    ) throws -> any CeremonyControlling
}

@MainActor
final class ApplePasskeyCeremonyDriver: CeremonyDriving {
    func capability(operation: PasskeyOperation) async -> PasskeyCapability {
        switch operation {
        case .enroll:
            // Apple exposes platform registration, but no PRF capability preflight.
            return .unknown
        case .recover:
            // Assertions may use local, synced, or cross-device passkeys. Apple
            // does not expose whether an eligible credential supports PRF.
            return .unknown
        }
    }

    func start(
        request: CeremonyRequest,
        completion: @escaping @MainActor (Result<CeremonyResult, Error>) -> Void
    ) throws -> any CeremonyControlling {
        let controller = ApplePasskeyCeremonyController(completion: completion)
        try controller.start(request)
        return controller
    }
}

@MainActor
private final class ApplePasskeyCeremonyController: NSObject, CeremonyControlling {
    private static let challengeByteCount = 32

    private var authorizationController: ASAuthorizationController?
    private var completion: (@MainActor (Result<CeremonyResult, Error>) -> Void)?
    private var fallbackProfile: PasskeyKeyProfile?
    private var createdCredentialId: String?

    init(completion: @escaping @MainActor (Result<CeremonyResult, Error>) -> Void) {
        self.completion = completion
    }

    func start(_ request: CeremonyRequest) throws {
        switch request {
        case .create(let profile, _, let user):
            fallbackProfile = profile
            let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
                relyingPartyIdentifier: profile.relyingPartyId
            )
            let registration = provider.createCredentialRegistrationRequest(
                challenge: try randomChallenge(),
                name: user.name,
                userID: user.id
            )
            registration.userVerificationPreference = .required
            registration.prf = .inputValues(.saltInput1(profile.prfSalt))
            perform(requests: [registration], interaction: .interactive)
        case .recover(let profile, let credentialIds, let interaction):
            try performRecovery(
                profile: profile,
                credentialIds: credentialIds,
                interaction: interaction
            )
        }
    }

    func cancel() {
        authorizationController?.cancel()
        authorizationController = nil
    }

    private func performRecovery(
        profile: PasskeyKeyProfile,
        credentialIds: [String],
        interaction: PasskeyInteraction
    ) throws {
        let ids = try credentialIds.map(ByteCodec.base64URLDecode)
        let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: profile.relyingPartyId
        )
        let platformRequest = platformProvider.createCredentialAssertionRequest(
            challenge: try randomChallenge()
        )
        platformRequest.allowedCredentials = ids.map {
            ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0)
        }
        platformRequest.userVerificationPreference = .required
        platformRequest.prf = .inputValues(.saltInput1(profile.prfSalt))

        perform(requests: [platformRequest], interaction: interaction)
    }

    private func perform(
        requests: [ASAuthorizationRequest],
        interaction: PasskeyInteraction
    ) {
        let controller = ASAuthorizationController(authorizationRequests: requests)
        controller.delegate = self
        authorizationController = controller
        switch interaction {
        case .interactive:
            controller.performRequests()
        case .immediatelyAvailable:
            controller.performRequests(options: .preferImmediatelyAvailableCredentials)
        }
    }

    private func randomChallenge() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: Self.challengeByteCount)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            let error = NSError(domain: NSOSStatusErrorDomain, code: Int(status))
            throw PasskeyKeyError.operationFailed(
                diagnostic: "secure random generation failed",
                underlying: error
            )
        }
        return Data(bytes)
    }

    private func finish(_ result: Result<CeremonyResult, Error>) {
        guard let completion else { return }
        self.completion = nil
        authorizationController = nil
        completion(result)
    }

    private func data(from key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }
}

extension ApplePasskeyCeremonyController: ASAuthorizationControllerDelegate {
    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        if let registration = authorization.credential
            as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
            let credentialId = ByteCodec.base64URLEncode(registration.credentialID)
            guard let prf = registration.prf, prf.isSupported else {
                finish(.failure(PasskeyKeyError.unsupported(
                    diagnostic: "the authenticator does not support PRF"
                )))
                return
            }
            if let first = prf.first {
                finish(.success(CeremonyResult(
                    credentialId: credentialId,
                    prfOutput: data(from: first),
                    isPlatformAuthenticator: registration.attachment == .platform
                )))
                return
            }
            guard let profile = fallbackProfile else {
                finish(.failure(PasskeyKeyError.operationFailed(
                    diagnostic: "registration completed without PRF output"
                )))
                return
            }
            createdCredentialId = credentialId
            do {
                try performRecovery(
                    profile: profile,
                    credentialIds: [credentialId],
                    interaction: .interactive
                )
            } catch {
                finish(.failure(error))
            }
            return
        }

        if let assertion = authorization.credential
            as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
            guard let output = assertion.prf?.first else {
                finish(.failure(PasskeyKeyError.unsupported(
                    diagnostic: "the authenticator returned no PRF output"
                )))
                return
            }
            finish(.success(CeremonyResult(
                credentialId: ByteCodec.base64URLEncode(assertion.credentialID),
                prfOutput: data(from: output),
                isPlatformAuthenticator: assertion.attachment == .platform
            )))
            return
        }

        finish(.failure(PasskeyKeyError.unsupported(
            diagnostic: "authorization returned no PRF output"
        )))
    }

    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithError error: Error
    ) {
        if let authorizationError = error as? ASAuthorizationError,
           authorizationError.code == .canceled {
            let diagnostic = createdCredentialId == nil
                ? nil
                : "a passkey was created, but PRF evaluation was cancelled; no wrapped key is available"
            finish(.failure(PasskeyKeyError.cancelled(
                diagnostic: diagnostic,
                underlying: error
            )))
        } else {
            finish(.failure(PasskeyKeyError.operationFailed(
                diagnostic: "passkey authorization failed",
                underlying: error
            )))
        }
    }
}
