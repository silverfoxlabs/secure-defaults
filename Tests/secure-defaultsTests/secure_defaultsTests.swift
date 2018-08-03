import XCTest
import Security
@testable import SecureDefaults

protocol TestMockType {
    var name : String { set get }
    var age : Int { set get }
    var rememberMe : Bool { get set }
}

struct TestMock : PreferenceDomainType, TestMockType {
    static var name: String { return "com.silverfox.secure_defaults.testMock" }
    static var key: String { return "testMockKey" }
    static var tag: String { return "com.silverfox.secure_defaults.encryptionKey" }
    
    var name : String = ""
    var age : Int = 0
    var rememberMe = false
}

class secure_defaultsTests: XCTestCase {
    
    private static var _mock : TestMock = {
        let t = TestMock()
        t.register()
        return t
    }()

    var encryptedRSAPayload = ""
    var encryptedECDSAPayload = ""
    var encryptedSecureEnclavePayload = ""
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()

        let r = RSAEncryption<TestMock>()
        var e = ECDSAEncryption<TestMock>()

        do {
            try r.nuke()
            e.useSecureEnclave = false
            try e.nuke()
            e.useSecureEnclave = true
            try e.nuke()
        }
        catch {
            print("Could not nuke the encryption keys")
            print(error.localizedDescription)
        }
    }

    func testRSAEncryption() -> Void {
        let mock = TestMock(name: "Luke Skywalker", age: 35, rememberMe: true)
        let rsaProvider = RSAEncryption<TestMock>()

        do {
            let result = try rsaProvider.encrypt(input: mock)
            mock.save(encryptedPayload: result)
            encryptedRSAPayload = TestMock.encryptedPayload()
            print(encryptedRSAPayload)
            XCTAssertTrue(encryptedRSAPayload.isEmpty == false)
        }
        catch {
            XCTAssertFalse(true)
        }

    }
    func testRSADecryption() -> Void {

        //RSA
        do {
            let provider = RSAEncryption<TestMock>()
            let decryptedMock : TestMock = try provider.decrypt(input: encryptedRSAPayload)
            XCTAssert(decryptedMock.name == "Luke Skywalker", "Mock Name does not match")
            XCTAssertNotNil(decryptedMock)
        }
        catch {
            XCTAssert(true)
        }

    }
    func testECDSAEncryption() -> Void {
        let mock = TestMock(name: "Luke Skywalker", age: 35, rememberMe: true)
        let ecdsaProvider = ECDSAEncryption<TestMock>()

        do {
            let result = try ecdsaProvider.encrypt(input: mock)
            mock.save(encryptedPayload: result)
            encryptedECDSAPayload = TestMock.encryptedPayload()
            print(encryptedECDSAPayload)
            XCTAssertTrue(encryptedRSAPayload.isEmpty == false)
        }
        catch {
            XCTAssertFalse(true)
        }

    }
    func testECDSADecryption() -> Void {

        do {
            let provider = ECDSAEncryption<TestMock>()
            let decryptedMock : TestMock = try provider.decrypt(input: encryptedECDSAPayload)
            XCTAssert(decryptedMock.name == "Luke Skywalker", "Mock Name does not match")
            XCTAssertNotNil(decryptedMock)
        }
        catch {
            XCTAssert(true)
        }
    }
    func testECDSAEncryptionWithSecureEnclave() -> Void {
        let mock = TestMock(name: "Luke Skywalker", age: 35, rememberMe: true)
        var ecdsaProvider = ECDSAEncryption<TestMock>()
        ecdsaProvider.useSecureEnclave = true

        do {
            let result = try ecdsaProvider.encrypt(input: mock)
            mock.save(encryptedPayload: result)
            encryptedECDSAPayload = TestMock.encryptedPayload()
            print(encryptedECDSAPayload)
            XCTAssertTrue(encryptedRSAPayload.isEmpty == false)
        }
        catch {
            XCTAssertFalse(true)
        }

    }
    func testECDSADecryptioWithSecureEnclave() -> Void {

    }
    
//    func testThatCanEncrypt() -> Void {
//
//        let mock = TestMock(name: "Luke Skywalker", age: 35, rememberMe: true)
//        let rsaProvider = RSAEncryption<TestMock>()
//
//        do {
//            let result = try rsaProvider.encrypt(input: mock)
//            mock.save(encryptedPayload: result)
//            encryptedRSAPayload = TestMock.encryptedPayload()
//            print(encryptedRSAPayload)
//            XCTAssertTrue(encryptedRSAPayload.isEmpty == false)
//        }
//        catch {
//            XCTAssertFalse(true)
//        }
//
//        let ecProvider = ECDSAEncryption<TestMock>()
//
//        do {
//            let result = try ecProvider.encrypt(input: mock)
//            mock.save(encryptedPayload: result)
//            encryptedECDSAPayload = TestMock.encryptedPayload()
//            print(encryptedRSAPayload)
//            XCTAssertTrue(encryptedECDSAPayload.isEmpty == false)
//        }
//        catch {
//            print(error.localizedDescription)
//            XCTAssertFalse(true)
//        }
//
//    }
//
//    func testThatCanEncryptWithSecureEnclave() -> Void {
//
//        let mock = TestMock(name: "Leia Organa", age: 25, rememberMe: true)
//        var ecProvider = ECDSAEncryption<TestMock>()
//        ecProvider.useSecureEnclave = true
//
//        do {
//            let result = try ecProvider.encrypt(input: mock)
//            mock.save(encryptedPayload: result)
//            encryptedSecureEnclavePayload = TestMock.encryptedPayload()
//            print(encryptedSecureEnclavePayload)
//            XCTAssertTrue(encryptedSecureEnclavePayload.isEmpty == false)
//        }
//        catch {
//            print(error.localizedDescription)
//            XCTAssertFalse(true)
//        }
//    }
//
//    func testThatCanDecrypt() -> Void {
//
//        do {
//
//            var decryptedMock : TestMock?
//            let rsaProvider = RSAEncryption<TestMock>()
//            var ecProvider = ECDSAEncryption<TestMock>()
//
//            //RSA
//            decryptedMock = try rsaProvider.decrypt(input: encryptedRSAPayload)
//            XCTAssertNotNil(decryptedMock)
//
//            //ECDSA
//            ecProvider.useSecureEnclave = false
//            decryptedMock = try ecProvider.decrypt(input: encryptedECDSAPayload)
//            XCTAssertNotNil(decryptedMock)
//
//            //ECDSA Secure Enclave
//            ecProvider.useSecureEnclave = true
//            decryptedMock = try ecProvider.decrypt(input: encryptedSecureEnclavePayload)
//            XCTAssertNotNil(decryptedMock)
//        }
//        catch {
//            XCTAssertFalse(true)
//        }
//    }

//    static var allTests = [
//        ("testThatCanEncrypt", testThatCanEncrypt),
//        ("testThatCanEncryptWithSecureEnclave", testThatCanEncryptWithSecureEnclave),
//        ("testThatCanDecrypt", testThatCanDecrypt),
//    ]
}
