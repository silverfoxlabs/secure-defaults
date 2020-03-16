import XCTest
import Security
@testable import SecureDefaults

struct TestMock : PreferenceDomainType, Codable {
    typealias EncryptedData = String

    static var name: String {
        return "com.silverfox.secureDefaults.testMock"
    }
    
    static var key: String {
        return "testMockKey"
    }
    
    static var tag: String {
        return "com.silverfox.secure_defaults.encryptionKey"
    }
    
    var name : String = "SilverFoxLabsTestKey"
    var age : Int = 0
    var rememberMe = false
}

class secure_defaultsTests: XCTestCase {
    
    var didRegisterMock = false
    
    var rsaProvider = UserDefaultsEncryption<TestMock>( EncryptionType.rsa(.rsaSignatureDigestPSSSHA512))
    var ecProvider = UserDefaultsEncryption<TestMock>(EncryptionType.ecdsa(.ecdsaSignatureDigestX962SHA512))
    
    var encryptedRSAPayload = ""
    var encryptedECDSAPayload = ""
    var encryptedSecureEnclavePayload = ""
    
    override func setUp() {
        super.setUp()
        
        if didRegisterMock == false {
            try? TestMock().register()
            didRegisterMock = true
        }
    }
    
    override func tearDown() {
        super.tearDown()
        
        do {
            try rsaProvider.nuke()
            try ecProvider.nuke()
        }
        catch {
            XCTAssertFalse(true)
            print(error.localizedDescription)
        }
    }
    
    func testThatCanEncrypt() -> Void {
        
        let mock = TestMock(name: "Luke Skywalker", age: 35, rememberMe: true)
        let rsaProvider = UserDefaultsEncryption<TestMock>(.rsa(.rsaSignatureDigestPSSSHA512))
        
        do {
            let result = try rsaProvider.encrypt(data: mock)
            try mock.save(encrypted: result)
            encryptedRSAPayload = try TestMock.encryptedData()
            XCTAssertTrue(encryptedRSAPayload.isEmpty == false)
        }
        catch {
            XCTAssertFalse(true)
        }
        
        let ecProvider = UserDefaultsEncryption<TestMock>(.ecdsa(.ecdsaSignatureDigestX962SHA512))
        
        do {
            let result = try ecProvider.encrypt(data: mock)
            try mock.save(encrypted: result)
            encryptedECDSAPayload = try TestMock.encryptedData()
            XCTAssertTrue(encryptedECDSAPayload.isEmpty == false)
        }
        catch {
            XCTAssertFalse(true)
        }
        
    }
    
    func testThatCanDecrypt() -> Void {
        
        do {
            
            var decryptedMock : TestMock?
            
            //RSA
            decryptedMock = try rsaProvider.decrypt(data: encryptedRSAPayload)
            XCTAssertNotNil(decryptedMock)
            
            //ECDSA
            decryptedMock = nil
            decryptedMock = try ecProvider.decrypt(data: encryptedECDSAPayload)
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
