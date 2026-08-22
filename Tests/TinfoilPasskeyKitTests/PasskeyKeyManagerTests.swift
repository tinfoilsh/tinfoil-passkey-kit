import Foundation
import XCTest
@testable import TinfoilPasskeyKit

@MainActor
final class PasskeyKeyManagerTests: XCTestCase {
    private let profile = try! PasskeyKeyProfile(
        version: 1,
        relyingPartyId: "example.com",
        prfSalt: Data("test-prf".utf8),
        hkdfInfo: Data("test-kek".utf8)
    )
    private let user = PasskeyUser(
        id: Data([9, 8, 7]),
        name: "person@example.com"
    )
    private let key = Data((0..<32).map(UInt8.init))

    func testCreatesAndRecoversWrappedKey() async throws {
        let storage = MemoryPasskeyKeyStorage()
        let driver = TestCeremonyDriver(behaviors: [
            .immediate(.success(result())),
            .immediate(.success(result(isPlatformAuthenticator: false)))
        ])
        let manager = try makeManager(driver: driver, storage: storage)

        let created = try await manager.createAndWrapKey(user: user, key: key)
        let recovered = try await manager.recoverKey(wrappedKeys: [created.wrappedKey])

        XCTAssertEqual(created.credentialId, "AQID")
        XCTAssertEqual(created.wrappedKey.profile, profile)
        XCTAssertEqual(recovered, RecoveredKey(credentialId: "AQID", key: key))
        XCTAssertEqual(try storage.loadCachedPRFResult()?.profile, profile)
        guard case .create(_, let relyingPartyName, _) = driver.requests[0] else {
            return XCTFail("Expected creation request")
        }
        XCTAssertEqual(relyingPartyName, "Example")
    }

    func testRejectsProfileMismatchMalformedInputAndOpaqueHandleLimit() async throws {
        let otherProfile = try PasskeyKeyProfile(
            version: 1,
            relyingPartyId: "example.com",
            prfSalt: Data("other".utf8),
            hkdfInfo: profile.hkdfInfo
        )
        let driver = TestCeremonyDriver()
        let manager = try makeManager(driver: driver)
        let mismatch = WrappedKey(
            profile: otherProfile,
            credentialId: "AQ",
            kekIvHex: String(repeating: "0", count: 24),
            wrappedKeyHex: String(repeating: "0", count: 96)
        )
        await assertError(.invalidInput) {
            _ = try await manager.recoverKey(wrappedKeys: [mismatch])
        }
        await assertError(.invalidInput) {
            _ = try await manager.createAndWrapKey(
                user: PasskeyUser(id: Data(count: 65), name: "person"),
                key: self.key
            )
        }
        await assertError(.invalidInput) {
            _ = try await manager.createAndWrapKey(user: self.user, key: Data(count: 31))
        }
        XCTAssertTrue(driver.requests.isEmpty)
    }

    func testNoStorageByDefaultAndMemoryStorageScopesCacheByProfile() async throws {
        let noStorageDriver = TestCeremonyDriver(behaviors: [.immediate(.success(result()))])
        let noStorage = try makeManager(driver: noStorageDriver)
        let created = try await noStorage.createAndWrapKey(user: user, key: key)
        XCTAssertNil(try noStorage.recoverKeyFromCache(wrappedKeys: [created.wrappedKey]))

        let storage = MemoryPasskeyKeyStorage()
        try storage.saveCachedPRFResult(CachedPRFResult(
            profile: profile,
            credentialId: "AQID",
            prfOutput: Data(repeating: 3, count: 32)
        ))
        let matching = try makeManager(driver: TestCeremonyDriver(), storage: storage)
        XCTAssertNotNil(try matching.recoverKeyFromCache(wrappedKeys: [created.wrappedKey]))

        let otherProfile = try PasskeyKeyProfile(
            version: 1,
            relyingPartyId: profile.relyingPartyId,
            prfSalt: profile.prfSalt,
            hkdfInfo: Data("other".utf8)
        )
        let other = try PasskeyKeyManager(
            profile: otherProfile,
            relyingPartyName: "Example",
            storage: storage,
            timeout: 1,
            ceremonyDriver: TestCeremonyDriver()
        )
        XCTAssertNil(try other.rewrapKeyFromCache(key: key))
    }

    func testCacheMissMalformedAndTamperedRecordsReturnNil() async throws {
        let storage = MemoryPasskeyKeyStorage()
        let driver = TestCeremonyDriver(behaviors: [.immediate(.success(result()))])
        let manager = try makeManager(driver: driver, storage: storage)
        let created = try await manager.createAndWrapKey(user: user, key: key)

        let stranger = WrappedKey(
            profile: profile,
            credentialId: "BAUG",
            kekIvHex: created.wrappedKey.kekIvHex,
            wrappedKeyHex: created.wrappedKey.wrappedKeyHex
        )
        XCTAssertNil(try manager.recoverKeyFromCache(wrappedKeys: [stranger]))

        var ciphertext = try ByteCodec.hexDecode(created.wrappedKey.wrappedKeyHex)
        ciphertext[0] ^= .max
        let tampered = WrappedKey(
            profile: profile,
            credentialId: created.credentialId,
            kekIvHex: created.wrappedKey.kekIvHex,
            wrappedKeyHex: ByteCodec.hexEncode(ciphertext)
        )
        XCTAssertNil(try manager.recoverKeyFromCache(wrappedKeys: [tampered]))

        try storage.saveCachedPRFResult(CachedPRFResult(
            profile: profile,
            credentialId: "!",
            prfOutput: Data(count: 31)
        ))
        XCTAssertNil(try manager.rewrapKeyFromCache(key: key))
    }

    func testStorageFailuresDoNotDiscardSuccessfulResults() async throws {
        let storage = FailingStorage()
        let manager = try makeManager(
            driver: TestCeremonyDriver(behaviors: [
                .immediate(.success(result())),
                .immediate(.success(result(isPlatformAuthenticator: false)))
            ]),
            storage: storage
        )

        let created = try await manager.createAndWrapKey(user: user, key: key)
        let recovered = try await manager.recoverKey(wrappedKeys: [created.wrappedKey])
        XCTAssertEqual(created.credentialId, "AQID")
        XCTAssertEqual(recovered.key, key)
        XCTAssertNil(try manager.recoverKeyFromCache(wrappedKeys: [created.wrappedKey]))
        XCTAssertNil(try manager.rewrapKeyFromCache(key: key))
        manager.clearLocalState()
    }

    func testRecoveryCachesSuccessfulCeremonyBeforeDecryption() async throws {
        let storage = MemoryPasskeyKeyStorage()
        let ceremonyResult = result(prfOutput: Data(repeating: 9, count: 32))
        let manager = try makeManager(
            driver: TestCeremonyDriver(behaviors: [.immediate(.success(ceremonyResult))]),
            storage: storage
        )
        let wrapped = fixtureWrappedKey(
            credentialId: ceremonyResult.credentialId,
            prfOutput: Data(repeating: 3, count: 32)
        )

        do {
            _ = try await manager.recoverKey(wrappedKeys: [wrapped])
            XCTFail("Expected authenticated decryption to fail")
        } catch {
            guard case PasskeyKeyError.operationFailed = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }

        XCTAssertEqual(try storage.loadCachedPRFResult()?.prfOutput, ceremonyResult.prfOutput)
        XCTAssertEqual(try storage.loadLocalCredentialId(), ceremonyResult.credentialId)
    }

    func testPreferredCredentialAndImmediateModeReachDriver() async throws {
        let driver = TestCeremonyDriver(behaviors: [
            .immediate(.success(result(
                credentialId: "Ag",
                prfOutput: Data(count: 32),
                isPlatformAuthenticator: false
            )))
        ])
        let manager = try makeManager(driver: driver)
        let first = fixtureWrappedKey(credentialId: "AQ", prfOutput: Data(count: 32))
        let second = fixtureWrappedKey(credentialId: "Ag", prfOutput: Data(count: 32))

        _ = try await manager.recoverKey(
            wrappedKeys: [first, second],
            preferredCredentialId: "Ag",
            interaction: .immediatelyAvailable
        )

        guard case .recover(_, let ids, let interaction) = try XCTUnwrap(
            driver.requests.first
        ) else {
            return XCTFail("Expected recovery request")
        }
        XCTAssertEqual(ids, ["Ag", "AQ"])
        guard case .immediatelyAvailable = interaction else {
            return XCTFail("Expected immediate mode")
        }
    }

    func testEvaluateCredentialReturnsDefensivePRFOutput() async throws {
        let storage = MemoryPasskeyKeyStorage()
        let source = Data(repeating: 7, count: 32)
        let driver = TestCeremonyDriver(behaviors: [
            .immediate(.success(result(prfOutput: source)))
        ])
        let manager = try makeManager(
            driver: driver,
            storage: storage
        )

        let evaluated = try await manager.evaluateCredential(
            credentialIds: ["AQID"],
            interaction: .immediatelyAvailable
        )
        var exposed = evaluated.prfResult.output
        exposed[0] = 0

        XCTAssertEqual(evaluated.credentialId, "AQID")
        XCTAssertEqual(source[0], 7)
        XCTAssertEqual(try storage.loadCachedPRFResult()?.prfOutput[0], 7)
        guard case .recover(_, _, let interaction) = try XCTUnwrap(
            driver.requests.first
        ) else {
            return XCTFail("Expected evaluation request")
        }
        guard case .immediatelyAvailable = interaction else {
            return XCTFail("Expected immediate evaluation")
        }
    }

    func testExplicitPRFMethodsIgnoreCeremoniesAndStorageFailures() throws {
        let driver = TestCeremonyDriver()
        let storage = FailingStorage()
        let manager = try makeManager(driver: driver, storage: storage)
        let keyMaterial = Data((0..<32).map(UInt8.init))
        let prfOutput = Data((0..<32).map { UInt8(255 - $0) })

        let wrappedKey = try manager.wrapKeyWithPRFResult(
            keyMaterial: keyMaterial,
            credentialId: "AQ",
            prfResult: PRFResult(output: prfOutput)
        )
        let unwrapped = try manager.unwrapKeyWithPRFResult(
            wrappedKey: wrappedKey,
            prfResult: PRFResult(output: prfOutput)
        )

        XCTAssertEqual(unwrapped, keyMaterial)
        XCTAssertEqual(wrappedKey.profile, profile)
        XCTAssertTrue(driver.requests.isEmpty)
        XCTAssertEqual(storage.callCount, 0)
    }

    func testExplicitPRFMethodsValidateInputs() throws {
        let manager = try makeManager(driver: TestCeremonyDriver())
        let prfResult = PRFResult(output: Data(count: 32))

        XCTAssertThrowsError(try manager.wrapKeyWithPRFResult(
            keyMaterial: Data(count: 31),
            credentialId: "AQ",
            prfResult: prfResult
        ))
        XCTAssertThrowsError(try manager.wrapKeyWithPRFResult(
            keyMaterial: Data(count: 32),
            credentialId: "AB",
            prfResult: prfResult
        ))
        XCTAssertThrowsError(try manager.wrapKeyWithPRFResult(
            keyMaterial: Data(count: 32),
            credentialId: "AQ",
            prfResult: PRFResult(output: Data(count: 31))
        ))

        let wrappedKey = try manager.wrapKeyWithPRFResult(
            keyMaterial: Data(count: 32),
            credentialId: "AQ",
            prfResult: prfResult
        )
        XCTAssertThrowsError(try manager.unwrapKeyWithPRFResult(
            wrappedKey: wrappedKey,
            prfResult: PRFResult(output: Data(count: 31))
        ))
        let otherProfile = try PasskeyKeyProfile(
            version: 1,
            relyingPartyId: profile.relyingPartyId,
            prfSalt: profile.prfSalt,
            hkdfInfo: Data("other".utf8)
        )
        XCTAssertThrowsError(try manager.unwrapKeyWithPRFResult(
            wrappedKey: WrappedKey(
                profile: otherProfile,
                credentialId: wrappedKey.credentialId,
                kekIvHex: wrappedKey.kekIvHex,
                wrappedKeyHex: wrappedKey.wrappedKeyHex
            ),
            prfResult: prfResult
        ))

        var ciphertext = try ByteCodec.hexDecode(wrappedKey.wrappedKeyHex)
        ciphertext[0] ^= .max
        XCTAssertThrowsError(try manager.unwrapKeyWithPRFResult(
            wrappedKey: WrappedKey(
                profile: wrappedKey.profile,
                credentialId: wrappedKey.credentialId,
                kekIvHex: wrappedKey.kekIvHex,
                wrappedKeyHex: ByteCodec.hexEncode(ciphertext)
            ),
            prfResult: prfResult
        )) { error in
            guard case PasskeyKeyError.operationFailed = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
    }

    func testExplicitPRFMethodsDoNotInspectActiveCeremony() async throws {
        let driver = TestCeremonyDriver(behaviors: [.pending])
        let manager = try makeManager(driver: driver)
        let ceremony = Task { @MainActor in
            try await manager.createAndWrapKey(user: user, key: key)
        }
        await Task.yield()

        let wrappedKey = try manager.wrapKeyWithPRFResult(
            keyMaterial: key,
            credentialId: "AQ",
            prfResult: PRFResult(output: Data(count: 32))
        )
        XCTAssertEqual(wrappedKey.credentialId, "AQ")

        manager.cancelActiveCeremony()
        do {
            _ = try await ceremony.value
            XCTFail("Expected cancellation")
        } catch {
            assertCategory(error, .cancelled)
        }
    }

    func testConcurrentOperationFailsAndCancellationAllowsNextOperation() async throws {
        let driver = TestCeremonyDriver(behaviors: [
            .pending,
            .immediate(.success(result()))
        ])
        let manager = try makeManager(driver: driver)
        let first = Task { @MainActor in
            try await manager.createAndWrapKey(user: user, key: key)
        }
        await Task.yield()

        await assertError(.operationInProgress) {
            _ = try await manager.createAndWrapKey(user: self.user, key: self.key)
        }
        first.cancel()
        do {
            _ = try await first.value
            XCTFail("Expected cancellation")
        } catch {
            assertCategory(error, .cancelled)
        }
        XCTAssertTrue(try XCTUnwrap(driver.controllers.first).isCancelled)
        _ = try await manager.createAndWrapKey(user: user, key: key)
    }

    func testExplicitCancellationOfPRFFallbackReturnsNoWrappedKey() async throws {
        let storage = MemoryPasskeyKeyStorage()
        let driver = TestCeremonyDriver(behaviors: [.pendingFallback(credentialId: "AQID")])
        let manager = try makeManager(driver: driver, storage: storage)
        let operation = Task { @MainActor in
            try await manager.createAndWrapKey(user: user, key: key)
        }
        await Task.yield()

        manager.cancelActiveCeremony()
        do {
            _ = try await operation.value
            XCTFail("Expected fallback cancellation")
        } catch {
            assertCategory(error, .cancelled)
        }
        XCTAssertEqual(driver.partialCredentialId, "AQID")
        XCTAssertNil(try storage.loadCachedPRFResult())
    }

    func testTimeoutIgnoresLateCallbackAndNextCeremonyWorks() async throws {
        let storage = MemoryPasskeyKeyStorage()
        let driver = TestCeremonyDriver(behaviors: [
            .pending,
            .immediate(.success(result()))
        ])
        let manager = try makeManager(driver: driver, timeout: 0.01, storage: storage)
        let first = Task { @MainActor in
            try await manager.createAndWrapKey(user: user, key: key)
        }

        try await Task.sleep(for: .milliseconds(30))
        do {
            _ = try await first.value
            XCTFail("Expected timeout")
        } catch {
            assertCategory(error, .timeout)
        }
        XCTAssertTrue(try XCTUnwrap(driver.controllers.first).isCancelled)
        driver.completePending(.success(result(prfOutput: Data(repeating: 9, count: 32))))
        await Task.yield()
        XCTAssertNil(try storage.loadCachedPRFResult())

        _ = try await manager.createAndWrapKey(user: user, key: key)
        XCTAssertNotNil(try storage.loadCachedPRFResult())
    }

    func testClearLocalStateClearsBothMemoryValues() throws {
        let storage = MemoryPasskeyKeyStorage()
        try storage.saveCachedPRFResult(CachedPRFResult(
            profile: profile,
            credentialId: "AQ",
            prfOutput: Data(count: 32)
        ))
        try storage.saveLocalCredentialId("AQ")
        let manager = try makeManager(driver: TestCeremonyDriver(), storage: storage)

        manager.clearLocalState()

        XCTAssertNil(try storage.loadCachedPRFResult())
        XCTAssertNil(try storage.loadLocalCredentialId())
    }

    func testCapabilitySeparatesOperationsThroughDriver() async throws {
        let driver = TestCeremonyDriver()
        driver.enrollCapability = .unsupported
        driver.recoverCapability = .unknown
        let manager = try makeManager(driver: driver)

        let enroll = await manager.capability(operation: .enroll)
        let recover = await manager.capability(operation: .recover)

        guard case .unsupported = enroll, case .unknown = recover else {
            return XCTFail("Unexpected capabilities")
        }
        XCTAssertEqual(driver.capabilityOperations.count, 2)
    }

    private func makeManager(
        driver: TestCeremonyDriver,
        timeout: TimeInterval = 1,
        storage: (any PasskeyKeyStorage)? = nil
    ) throws -> PasskeyKeyManager {
        try PasskeyKeyManager(
            profile: profile,
            relyingPartyName: "Example",
            storage: storage,
            timeout: timeout,
            ceremonyDriver: driver
        )
    }

    private func result(
        credentialId: String = "AQID",
        prfOutput: Data = Data(repeating: 3, count: 32),
        isPlatformAuthenticator: Bool = true
    ) -> CeremonyResult {
        CeremonyResult(
            credentialId: credentialId,
            prfOutput: prfOutput,
            isPlatformAuthenticator: isPlatformAuthenticator
        )
    }

    private func fixtureWrappedKey(credentialId: String, prfOutput: Data) -> WrappedKey {
        try! KeyWrappingCrypto.wrap(
            profile: profile,
            credentialId: credentialId,
            prfOutput: prfOutput,
            key: key,
            iv: Data(count: 12)
        )
    }

    private enum ExpectedCategory {
        case invalidInput
        case cancelled
        case timeout
        case operationInProgress
    }

    private func assertError(
        _ category: ExpectedCategory,
        operation: () async throws -> Void
    ) async {
        do {
            try await operation()
            XCTFail("Expected an error")
        } catch {
            assertCategory(error, category)
        }
    }

    private func assertCategory(_ error: Error, _ category: ExpectedCategory) {
        switch (error, category) {
        case (PasskeyKeyError.invalidInput, .invalidInput),
             (PasskeyKeyError.cancelled, .cancelled),
             (PasskeyKeyError.timeout, .timeout),
             (PasskeyKeyError.operationInProgress, .operationInProgress):
            break
        default:
            XCTFail("Unexpected error: \(error)")
        }
    }
}

@MainActor
private final class TestCeremonyController: CeremonyControlling {
    private(set) var isCancelled = false

    func cancel() {
        isCancelled = true
    }
}

@MainActor
private final class TestCeremonyDriver: CeremonyDriving {
    enum Behavior {
        case immediate(Result<CeremonyResult, Error>)
        case pending
        case pendingFallback(credentialId: String)
    }

    var enrollCapability: PasskeyCapability = .unknown
    var recoverCapability: PasskeyCapability = .unknown
    private(set) var capabilityOperations: [PasskeyOperation] = []
    private(set) var requests: [CeremonyRequest] = []
    private(set) var controllers: [TestCeremonyController] = []
    private(set) var partialCredentialId: String?
    private var behaviors: [Behavior]
    private var pendingCompletions: [@MainActor (Result<CeremonyResult, Error>) -> Void] = []

    init(behaviors: [Behavior] = []) {
        self.behaviors = behaviors
    }

    func capability(operation: PasskeyOperation) async -> PasskeyCapability {
        capabilityOperations.append(operation)
        switch operation {
        case .enroll: return enrollCapability
        case .recover: return recoverCapability
        }
    }

    func start(
        request: CeremonyRequest,
        completion: @escaping @MainActor (Result<CeremonyResult, Error>) -> Void
    ) throws -> any CeremonyControlling {
        requests.append(request)
        let controller = TestCeremonyController()
        controllers.append(controller)
        let behavior = behaviors.isEmpty ? .pending : behaviors.removeFirst()
        switch behavior {
        case .immediate(let result):
            completion(result)
        case .pending:
            pendingCompletions.append(completion)
        case .pendingFallback(let credentialId):
            partialCredentialId = credentialId
            pendingCompletions.append(completion)
        }
        return controller
    }

    func completePending(_ result: Result<CeremonyResult, Error>) {
        guard !pendingCompletions.isEmpty else { return }
        pendingCompletions.removeFirst()(result)
    }
}

@MainActor
private final class FailingStorage: PasskeyKeyStorage {
    struct Failure: Error {}

    private(set) var callCount = 0

    func loadCachedPRFResult() throws -> CachedPRFResult? {
        callCount += 1
        throw Failure()
    }

    func saveCachedPRFResult(_ result: CachedPRFResult) throws {
        callCount += 1
        throw Failure()
    }

    func loadLocalCredentialId() throws -> String? {
        callCount += 1
        throw Failure()
    }

    func saveLocalCredentialId(_ credentialId: String) throws {
        callCount += 1
        throw Failure()
    }

    func clear() throws {
        callCount += 1
        throw Failure()
    }
}
