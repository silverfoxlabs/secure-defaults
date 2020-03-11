import XCTest
import Security
@testable import secure_defaults

struct TestMock : PreferenceDomainType {
    static var name: String {
        return "com.silverfox.secure_defaults.testMock"
    }
    
    static var key: String {
        return "testMockKey"
    }
    
    static var tag: String {
        return "com.silverfox.secure_defaults.encryptionKey"
    }
    
    var name : String = ""
    var age : Int = 0
    var rememberMe = false
}

class secure_defaultsTests: XCTestCase {
    
    var didRegisterMock = false
    
    var rsaProvider = RSAEncryption<TestMock>()
    var ecProvider = ECDSAEncryption<TestMock>()
    
    var encryptedRSAPayload = ""
    var encryptedECDSAPayload = ""
    var encryptedSecureEnclavePayload = ""
    
    override func setUp() {
        super.setUp()
        
        if didRegisterMock == false {
            TestMock().register()
            didRegisterMock = true
            
            //get and unlock the Keychain
            
        }
        
        
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
            XCTAssertTrue(encryptedRSAPayload.isEmpty == false)
        }
        catch {
            XCTAssertFalse(true)
        }
        
        let ecProvider = ECDSAEncryption<TestMock>()
        
        do {
            let result = try ecProvider.encrypt(input: mock)
            mock.save(encryptedPayload: result)
            encryptedECDSAPayload = TestMock.encryptedPayload()
            XCTAssertTrue(encryptedECDSAPayload.isEmpty == false)
        }
        catch {
            XCTAssertFalse(true)
        }
        
    }
    
    func testThatCanEncryptWithSecureEnclave() -> Void {
        let mock = TestMock(name: "Leia Organa", age: 25, rememberMe: true)
        var ecProvider = ECDSAEncryption<TestMock>()
        ecProvider.useSecureEnclave = true
        
        do {
            let result = try ecProvider.encrypt(input: mock)
            mock.save(encryptedPayload: result)
            encryptedSecureEnclavePayload = TestMock.encryptedPayload()
            XCTAssertTrue(encryptedSecureEnclavePayload.isEmpty == false)
        }
        catch {
            XCTAssertFalse(true)
        }
    }
    
    func testThatCanDecrypt() -> Void {
        
        do {
            
            var decryptedMock : TestMock?
            
            //RSA
            decryptedMock = try rsaProvider.decrypt(input: encryptedRSAPayload)
            XCTAssertNotNil(decryptedMock)
            
            //ECDSA
            decryptedMock = nil
            ecProvider.useSecureEnclave = false
            decryptedMock = try ecProvider.decrypt(input: encryptedECDSAPayload)
            XCTAssertNotNil(decryptedMock)
            
            //ECDSA Secure Enclave
            decryptedMock = nil
            ecProvider.useSecureEnclave = true
            decryptedMock = try ecProvider.decrypt(input: encryptedSecureEnclavePayload)
            XCTAssertNotNil(decryptedMock)
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
