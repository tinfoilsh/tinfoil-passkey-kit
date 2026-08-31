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

    private let profile: PasskeyKeyProfile
    private let relyingPartyName: String
    private let storage: (any PasskeyKeyStorage)?
    private let timeout: TimeInterval
    private let ceremonyDriver: any CeremonyDriving
    private var activeCeremony: ActiveCeremony?

    public convenience init(
        profile: PasskeyKeyProfile,
        relyingPartyName: String,
        storage: (any PasskeyKeyStorage)? = nil,
        presentationAnchorProvider: any PasskeyPresentationAnchorProviding,
        timeout: TimeInterval = 60
    ) throws {
        try self.init(
            profile: profile,
            relyingPartyName: relyingPartyName,
            storage: storage,
            timeout: timeout,
            ceremonyDriver: ApplePasskeyCeremonyDriver(
                presentationAnchorProvider: presentationAnchorProvider
            )
        )
    }

    init(
        profile: PasskeyKeyProfile,
        relyingPartyName: String,
        storage: (any PasskeyKeyStorage)?,
        timeout: TimeInterval,
        ceremonyDriver: any CeremonyDriving
    ) throws {
        guard timeout.isFinite, timeout > 0 else {
            throw PasskeyKeyError.invalidInput(diagnostic: "timeout must be positive and finite")
        }
        guard !relyingPartyName.isEmpty else {
            throw PasskeyKeyError.invalidInput(
                diagnostic: "relying-party name must not be empty"
            )
        }
        self.profile = try Self.copy(profile)
        self.relyingPartyName = relyingPartyName
        self.storage = storage
        self.timeout = timeout
        self.ceremonyDriver = ceremonyDriver
    }

    public func capability(operation: PasskeyOperation) async -> PasskeyCapability {
        await ceremonyDriver.capability(operation: operation)
    }

    public func createAndWrapKey(user: PasskeyUser, key: Data) async throws -> CreatedWrappedKey {
        try validate(user: user)
        try KeyWrappingCrypto.validateKey(key)
        let result = try await runCeremony(
            request: .create(
                profile: profile,
                relyingPartyName: relyingPartyName,
                user: user
            )
        )
        recordSuccessfulCeremony(result)
        let wrapped = try wrapKeyWithPRFResult(
            keyMaterial: key,
            credentialId: result.credentialId,
            prfResult: PRFResult(output: result.prfOutput)
        )
        return CreatedWrappedKey(credentialId: result.credentialId, wrappedKey: wrapped)
    }

    public func recoverKey(
        wrappedKeys: [WrappedKey],
        preferredCredentialId: String? = nil,
        interaction: PasskeyInteraction = .interactive
    ) async throws -> RecoveredKey {
        let usableKeys = try usableWrappedKeys(wrappedKeys)
        let result = try await evaluateCredentialResult(
            credentialIds: usableKeys.map(\.credentialId),
            preferredCredentialId: preferredCredentialId,
            interaction: interaction
        )
        guard let wrapped = usableKeys.first(where: {
            $0.credentialId == result.credentialId
        }) else {
            throw PasskeyKeyError.invalidInput(
                diagnostic: "credential has no matching wrapped key"
            )
        }
        let key = try unwrapKeyWithPRFResult(
            wrappedKey: wrapped,
            prfResult: PRFResult(output: result.prfOutput)
        )
        return RecoveredKey(credentialId: result.credentialId, key: key)
    }

    public func evaluateCredential(
        credentialIds: [String],
        preferredCredentialId: String? = nil,
        interaction: PasskeyInteraction = .interactive
    ) async throws -> EvaluatedCredential {
        let result = try await evaluateCredentialResult(
            credentialIds: credentialIds,
            preferredCredentialId: preferredCredentialId,
            interaction: interaction
        )
        return EvaluatedCredential(
            credentialId: result.credentialId,
            prfResult: PRFResult(output: Self.copy(result.prfOutput))
        )
    }

    public func wrapKeyWithPRFResult(
        keyMaterial: Data,
        credentialId: String,
        prfResult: PRFResult
    ) throws -> WrappedKey {
        try KeyWrappingCrypto.validateKey(keyMaterial)
        try KeyWrappingCrypto.validatePRFOutput(prfResult.output)
        _ = try ByteCodec.base64URLDecode(credentialId)
        let credentialId = Self.copy(credentialId)
        return try KeyWrappingCrypto.wrap(
            profile: Self.copy(profile),
            credentialId: credentialId,
            prfOutput: Self.copy(prfResult.output),
            key: Self.copy(keyMaterial)
        )
    }

    public func unwrapKeyWithPRFResult(
        wrappedKey: WrappedKey,
        prfResult: PRFResult
    ) throws -> Data {
        let wrappedKey = WrappedKey(
            profile: try Self.copy(wrappedKey.profile),
            credentialId: wrappedKey.credentialId,
            kekIvHex: wrappedKey.kekIvHex,
            wrappedKeyHex: wrappedKey.wrappedKeyHex
        )
        try KeyWrappingCrypto.validatePRFOutput(prfResult.output)
        try KeyWrappingCrypto.validateWrappedKey(wrappedKey, profile: profile)
        return try KeyWrappingCrypto.unwrap(
            profile: profile,
            prfOutput: Self.copy(prfResult.output),
            wrapped: wrappedKey
        )
    }

    public func recoverKeyFromCache(
        wrappedKeys: [WrappedKey],
        preferredCredentialId: String? = nil
    ) throws -> RecoveredKey? {
        let usableKeys = try usableWrappedKeys(wrappedKeys)
        guard let cached = loadCachedResult(),
              let wrapped = usableKeys.first(where: {
                  $0.credentialId == cached.credentialId
              }) else {
            return nil
        }
        do {
            return RecoveredKey(
                credentialId: cached.credentialId,
                key: try unwrapKeyWithPRFResult(
                    wrappedKey: wrapped,
                    prfResult: PRFResult(output: cached.prfOutput)
                )
            )
        } catch {
            return nil
        }
    }

    public func rewrapKeyFromCache(key: Data) throws -> WrappedKey? {
        try KeyWrappingCrypto.validateKey(key)
        guard let cached = loadCachedResult() else { return nil }
        return try wrapKeyWithPRFResult(
            keyMaterial: key,
            credentialId: cached.credentialId,
            prfResult: PRFResult(output: cached.prfOutput)
        )
    }

    public func clearLocalState() {
        do {
            try storage?.clear()
        } catch {}
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
                    let timeout = self.timeout
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

    /// Filter to the wrapped keys this manager can actually use. A
    /// malformed candidate (wrong profile, non-canonical credential ID,
    /// bad lengths) is skipped rather than failing the whole set, so one
    /// corrupt or foreign bundle cannot block recovery from the healthy
    /// ones. Throws only when no usable candidate remains.
    private func usableWrappedKeys(_ wrappedKeys: [WrappedKey]) throws -> [WrappedKey] {
        guard !wrappedKeys.isEmpty else {
            throw PasskeyKeyError.invalidInput(
                diagnostic: "at least one wrapped key is required"
            )
        }
        let usable = wrappedKeys.filter { wrapped in
            (try? KeyWrappingCrypto.validateWrappedKey(wrapped, profile: profile)) != nil
        }
        guard !usable.isEmpty else {
            throw PasskeyKeyError.invalidInput(
                diagnostic: "no wrapped key matches this profile and format"
            )
        }
        return usable
    }

    private func evaluateCredentialResult(
        credentialIds: [String],
        preferredCredentialId: String?,
        interaction: PasskeyInteraction
    ) async throws -> CeremonyResult {
        let result = try await runCeremony(
            request: .recover(
                profile: profile,
                credentialIds: try orderedCredentialIds(
                    credentialIds: credentialIds,
                    preferredCredentialId: preferredCredentialId
                ),
                interaction: interaction
            )
        )
        recordSuccessfulCeremony(result)
        return result
    }

    private func orderedCredentialIds(
        credentialIds: [String],
        preferredCredentialId: String?
    ) throws -> [String] {
        guard !credentialIds.isEmpty else {
            throw PasskeyKeyError.invalidInput(
                diagnostic: "at least one credential ID is required"
            )
        }
        var seen = Set<String>()
        // Skip candidates that are not canonical base64url instead of
        // failing the ceremony: one malformed ID (e.g. a legacy record
        // written by another client) must not block assertion against
        // the valid ones.
        let credentialIds = credentialIds
            .filter { seen.insert($0).inserted }
            .filter { (try? ByteCodec.base64URLDecode($0)) != nil }
        guard !credentialIds.isEmpty else {
            throw PasskeyKeyError.invalidInput(
                diagnostic: "no credential ID is valid unpadded base64url"
            )
        }
        let preferred = preferredCredentialId ?? loadLocalCredentialId()
        guard let preferred, credentialIds.contains(preferred) else {
            return credentialIds
        }
        return [preferred] + credentialIds.filter { $0 != preferred }
    }

    private static func copy(_ data: Data) -> Data {
        data.withUnsafeBytes { Data($0) }
    }

    private static func copy(_ string: String) -> String {
        String(decoding: Data(string.utf8), as: UTF8.self)
    }

    private static func copy(_ profile: PasskeyKeyProfile) throws -> PasskeyKeyProfile {
        try PasskeyKeyProfile(
            version: profile.version,
            relyingPartyId: profile.relyingPartyId,
            prfSalt: copy(profile.prfSalt),
            hkdfInfo: copy(profile.hkdfInfo)
        )
    }

    private func recordSuccessfulCeremony(_ result: CeremonyResult) {
        do {
            try storage?.saveCachedPRFResult(
                CachedPRFResult(
                    profile: profile,
                    credentialId: result.credentialId,
                    prfOutput: result.prfOutput
                )
            )
        } catch {}
        if result.isPlatformAuthenticator {
            do {
                try storage?.saveLocalCredentialId(result.credentialId)
            } catch {}
        }
    }

    private func loadCachedResult() -> CachedPRFResult? {
        do {
            guard let result = try storage?.loadCachedPRFResult(),
                  result.profile == profile,
                  result.prfOutput.count == KeyWrappingCrypto.prfOutputByteCount,
                  (try? ByteCodec.base64URLDecode(result.credentialId)) != nil else {
                return nil
            }
            return result
        } catch {
            return nil
        }
    }

    private func loadLocalCredentialId() -> String? {
        do {
            return try storage?.loadLocalCredentialId()
        } catch {
            return nil
        }
    }
}
