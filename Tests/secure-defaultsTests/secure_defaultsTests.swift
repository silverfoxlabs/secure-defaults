import XCTest
import Security
@testable import SecureDefaults

struct TestMockECDSA : PreferenceDomainType {
    static var name: String { return "com.silverfox.secure_defaults.testMock.ecdsa"}
    static var key: String { return "testMockKeyECDSA" }
    static var tag: String { return "com.silverfox.secure_defaults.encryptionKey.ecdsa" }

    var name : String = ""
    var age : Int = 0
    var rememberMe = false
}


struct TestMock : PreferenceDomainType {
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
    
    private static var _mockECDSA : TestMockECDSA = {
        let t = TestMockECDSA()
        t.register()
        return t
    }()
    
    var didRegisterMock = false
    
    var rsaProvider = RSAEncryption<TestMock>()
    var ecProvider = ECDSAEncryption<TestMockECDSA>()
    
    var encryptedRSAPayload = ""
    var encryptedECDSAPayload = ""
    var encryptedSecureEnclavePayload = ""
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
        
        do {
            try rsaProvider.nuke()
            ecProvider.useSecureEnclave = false
            try ecProvider.nuke()
            ecProvider.useSecureEnclave = true
            try ecProvider.nuke()
        }
        catch {
            print(error.localizedDescription)
        }
    }
    
    func testThatCanEncrypt() -> Void {
        
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
        
        let mockECDSA = TestMockECDSA(name: "Luke Skywalker", age: 35, rememberMe: true)
        let ecProvider = ECDSAEncryption<TestMockECDSA>()
        
        do {
            let result = try ecProvider.encrypt(input: mockECDSA)
            mock.save(encryptedPayload: result)
            encryptedECDSAPayload = TestMock.encryptedPayload()
            print(encryptedRSAPayload)
            XCTAssertTrue(encryptedECDSAPayload.isEmpty == false)
        }
        catch {
            print(error.localizedDescription)
            XCTAssertFalse(true)
        }
        
    }
    
    func testThatCanEncryptWithSecureEnclave() -> Void {
       
        let mock = TestMockECDSA(name: "Leia Organa", age: 25, rememberMe: true)
        var ecProvider = ECDSAEncryption<TestMockECDSA>()
        ecProvider.useSecureEnclave = true
        
        do {
            let result = try ecProvider.encrypt(input: mock)
            mock.save(encryptedPayload: result)
            encryptedSecureEnclavePayload = TestMock.encryptedPayload()
            print(encryptedSecureEnclavePayload)
            XCTAssertTrue(encryptedSecureEnclavePayload.isEmpty == false)
        }
        catch {
            print(error.localizedDescription)
            XCTAssertFalse(true)
        }
    }
    
    func testThatCanDecrypt() -> Void {
        
        do {
            
            var decryptedMock : TestMock?
            var decryptedMockECDSA : TestMockECDSA?
            
            //RSA
            decryptedMock = try rsaProvider.decrypt(input: encryptedRSAPayload)
            XCTAssertNotNil(decryptedMock)
            
            //ECDSA
            ecProvider.useSecureEnclave = false
            decryptedMockECDSA = try ecProvider.decrypt(input: encryptedECDSAPayload)
            XCTAssertNotNil(decryptedMockECDSA)
            
            //ECDSA Secure Enclave
            decryptedMockECDSA = nil
            ecProvider.useSecureEnclave = true
            decryptedMockECDSA = try ecProvider.decrypt(input: encryptedSecureEnclavePayload)
            XCTAssertNotNil(decryptedMockECDSA)
        }
        catch {
            XCTAssertFalse(true)
        }
    }
    
//    static var allTests = [
//        ("testThatCanEncrypt", testThatCanEncrypt),
//        ("testThatCanEncryptWithSecureEnclave", testThatCanEncryptWithSecureEnclave),
//        ("testThatCanDecrypt", testThatCanDecrypt),
//    ]
}
