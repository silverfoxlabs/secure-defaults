import XCTest
@testable import secure_defaults

class secure_defaultsTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        XCTAssertEqual(secure_defaults().text, "Hello, World!")
    }


    static var allTests = [
        ("testExample", testExample),
    ]
}
