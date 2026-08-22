import Foundation

@MainActor
public final class PasskeyKeyManager {
    private final class ActiveCeremony {
        let id: UUID
        let continuation: CheckedContinuation<CeremonyResult, Error>
        var controller: (any CeremonyControlling)?
        var timeoutTask: Task<Void, Never>?

        init(id: UUID, continuation: CheckedContinuation<CeremonyResult, Error>) {
            self.id = id
            self.continuation = continuation
        }
    }

    private let configuration: PasskeyKeyManagerConfiguration
    private let ceremonyDriver: any CeremonyDriving
    private let ceremonyMode: CeremonyMode
    private var activeCeremony: ActiveCeremony?
    private(set) var storageDiagnostic: Error?

    public init(configuration: PasskeyKeyManagerConfiguration) {
        self.configuration = configuration
        self.ceremonyDriver = ApplePasskeyCeremonyDriver()
        self.ceremonyMode = .interactive
    }

    init(
        configuration: PasskeyKeyManagerConfiguration,
        ceremonyDriver: any CeremonyDriving,
        ceremonyMode: CeremonyMode = .interactive
    ) {
        self.configuration = configuration
        self.ceremonyDriver = ceremonyDriver
        self.ceremonyMode = ceremonyMode
    }

    public func capability(operation: PasskeyOperation) async -> PasskeyCapability {
        await ceremonyDriver.capability(operation: operation)
    }

    public func createAndWrapKey(user: PasskeyUser, key: Data) async throws -> CreatedWrappedKey {
        try validate(user: user)
        try KeyWrappingCrypto.validateKey(key)
        let result = try await runCeremony(
            request: .create(
                profile: configuration.profile,
                user: user,
                mode: ceremonyMode
            )
        )
        let wrapped = try KeyWrappingCrypto.wrap(
            profile: configuration.profile,
            credentialId: result.credentialId,
            prfOutput: result.prfOutput,
            key: key
        )
        recordSuccessfulCeremony(result)
        return CreatedWrappedKey(credentialId: result.credentialId, wrappedKey: wrapped)
    }

    public func recoverKey(
        wrappedKeys: [WrappedKey],
        preferredCredentialId: String? = nil
    ) async throws -> RecoveredKey {
        try validate(wrappedKeys: wrappedKeys)
        let result = try await runCeremony(
            request: .recover(
                profile: configuration.profile,
                credentialIds: orderedCredentialIds(
                    wrappedKeys: wrappedKeys,
                    preferredCredentialId: preferredCredentialId
                ),
                mode: ceremonyMode
            )
        )
        guard let wrapped = wrappedKeys.first(where: {
            $0.credentialId == result.credentialId
        }) else {
            throw PasskeyKeyError.invalidInput(
                diagnostic: "credential has no matching wrapped key"
            )
        }
        let key = try KeyWrappingCrypto.unwrap(
            profile: configuration.profile,
            prfOutput: result.prfOutput,
            wrapped: wrapped
        )
        recordSuccessfulCeremony(result)
        return RecoveredKey(credentialId: result.credentialId, key: key)
    }

    public func recoverKeyFromCache(
        wrappedKeys: [WrappedKey],
        preferredCredentialId: String? = nil
    ) throws -> RecoveredKey? {
        try validate(wrappedKeys: wrappedKeys)
        guard let cached = loadCachedResult(),
              let wrapped = wrappedKeys.first(where: {
                  $0.credentialId == cached.credentialId
              }) else {
            return nil
        }
        do {
            return RecoveredKey(
                credentialId: cached.credentialId,
                key: try KeyWrappingCrypto.unwrap(
                    profile: configuration.profile,
                    prfOutput: cached.prfOutput,
                    wrapped: wrapped
                )
            )
        } catch {
            return nil
        }
    }

    public func rewrapKeyFromCache(key: Data) throws -> WrappedKey? {
        try KeyWrappingCrypto.validateKey(key)
        guard let cached = loadCachedResult() else { return nil }
        return try KeyWrappingCrypto.wrap(
            profile: configuration.profile,
            credentialId: cached.credentialId,
            prfOutput: cached.prfOutput,
            key: key
        )
    }

    public func clearLocalState() {
        do {
            try configuration.storage?.clear()
        } catch {
            storageDiagnostic = error
        }
    }

    public func cancelActiveCeremony() {
        interruptActiveCeremony(with: .cancelled())
    }

    private func runCeremony(request: CeremonyRequest) async throws -> CeremonyResult {
        guard activeCeremony == nil else {
            throw PasskeyKeyError.operationInProgress
        }
        guard !Task.isCancelled else {
            throw PasskeyKeyError.cancelled(underlying: CancellationError())
        }

        let operationId = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let active = ActiveCeremony(id: operationId, continuation: continuation)
                activeCeremony = active
                do {
                    let controller = try ceremonyDriver.start(request: request) {
                        [weak self] result in
                        self?.settleCeremony(id: operationId, result: result)
                    }
                    guard activeCeremony?.id == operationId else {
                        return
                    }
                    active.controller = controller
                    let timeout = configuration.timeout
                    active.timeoutTask = Task { [weak self] in
                        do {
                            try await Task.sleep(for: .seconds(timeout))
                        } catch {
                            return
                        }
                        self?.timeoutCeremony(id: operationId)
                    }
                } catch {
                    settleCeremony(id: operationId, result: .failure(error))
                }
            }
        } onCancel: {
            Task { @MainActor [weak self] in
                self?.cancelCeremony(id: operationId)
            }
        }
    }

    private func cancelCeremony(id: UUID) {
        guard activeCeremony?.id == id else { return }
        interruptActiveCeremony(with: .cancelled(underlying: CancellationError()))
    }

    private func timeoutCeremony(id: UUID) {
        guard activeCeremony?.id == id else { return }
        interruptActiveCeremony(with: .timeout())
    }

    private func interruptActiveCeremony(with error: PasskeyKeyError) {
        guard let active = activeCeremony else { return }
        let controller = active.controller
        settleCeremony(id: active.id, result: .failure(error))
        controller?.cancel()
    }

    private func settleCeremony(id: UUID, result: Result<CeremonyResult, Error>) {
        guard let active = activeCeremony, active.id == id else { return }
        activeCeremony = nil
        active.timeoutTask?.cancel()
        switch result {
        case .success(let ceremonyResult):
            do {
                try KeyWrappingCrypto.validatePRFOutput(ceremonyResult.prfOutput)
                _ = try ByteCodec.base64URLDecode(ceremonyResult.credentialId)
                active.continuation.resume(returning: ceremonyResult)
            } catch {
                active.continuation.resume(throwing: error)
            }
        case .failure(let error):
            active.continuation.resume(throwing: mapCeremonyError(error))
        }
    }

    private func mapCeremonyError(_ error: Error) -> PasskeyKeyError {
        if let passkeyError = error as? PasskeyKeyError {
            return passkeyError
        }
        if error is CancellationError {
            return .cancelled(underlying: error)
        }
        return .operationFailed(
            diagnostic: "passkey ceremony failed",
            underlying: error
        )
    }

    private func validate(user: PasskeyUser) throws {
        guard !user.id.isEmpty, user.id.count <= 64 else {
            throw PasskeyKeyError.invalidInput(
                diagnostic: "user ID must contain between 1 and 64 bytes"
            )
        }
        guard !user.name.isEmpty else {
            throw PasskeyKeyError.invalidInput(diagnostic: "user name must not be empty")
        }
        if let displayName = user.displayName, displayName.isEmpty {
            throw PasskeyKeyError.invalidInput(
                diagnostic: "user display name must not be empty"
            )
        }
    }

    private func validate(wrappedKeys: [WrappedKey]) throws {
        guard !wrappedKeys.isEmpty else {
            throw PasskeyKeyError.invalidInput(
                diagnostic: "at least one wrapped key is required"
            )
        }
        for wrapped in wrappedKeys {
            try KeyWrappingCrypto.validateWrappedKey(
                wrapped,
                profile: configuration.profile
            )
        }
    }

    private func orderedCredentialIds(
        wrappedKeys: [WrappedKey],
        preferredCredentialId: String?
    ) -> [String] {
        var seen = Set<String>()
        let credentialIds = wrappedKeys.map(\.credentialId).filter { seen.insert($0).inserted }
        let preferred = preferredCredentialId ?? loadLocalCredentialId()
        guard let preferred, credentialIds.contains(preferred) else {
            return credentialIds
        }
        return [preferred] + credentialIds.filter { $0 != preferred }
    }

    private func recordSuccessfulCeremony(_ result: CeremonyResult) {
        do {
            try configuration.storage?.saveCachedPRFResult(
                CachedPRFResult(
                    profile: configuration.profile,
                    credentialId: result.credentialId,
                    prfOutput: result.prfOutput
                )
            )
        } catch {
            storageDiagnostic = error
        }
        if result.isPlatformAuthenticator {
            do {
                try configuration.storage?.saveLocalCredentialId(result.credentialId)
            } catch {
                storageDiagnostic = error
            }
        }
    }

    private func loadCachedResult() -> CachedPRFResult? {
        do {
            guard let result = try configuration.storage?.loadCachedPRFResult(),
                  result.profile == configuration.profile,
                  result.prfOutput.count == KeyWrappingCrypto.prfOutputByteCount,
                  (try? ByteCodec.base64URLDecode(result.credentialId)) != nil else {
                return nil
            }
            return result
        } catch {
            storageDiagnostic = error
            return nil
        }
    }

    private func loadLocalCredentialId() -> String? {
        do {
            return try configuration.storage?.loadLocalCredentialId()
        } catch {
            storageDiagnostic = error
            return nil
        }
    }
}
