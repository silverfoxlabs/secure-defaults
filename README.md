# secure-defaults
Secure your ```UserDefaults``` &  ```NSUserDefaults``` with encryption.

---

#### Supported platforms:

``` iOS 10+``` (tested)

``` macOS 10.10 ``` (tested)

``` tv0S 10+``` (untested)

``` watchOS 3+ ``` (untested)

---
#### Introduction
---

Developers use the ```UserDefaults``` mechanism to store default values for their apps.  Generally, when you have sensitive information - storing in the ```UserDefaults``` is inherently insecure.

One option is to use the ```Keychain``` ; using the keychain for app settings can be a bit hacky (say vs. a password or some simple data you want to store).

```secure_defaults``` offers a way to get the benefits of both approaches - storing your app settings (including sensitive ones) in your ```suite``` in the ```UserDefaults```, and ___encrypting___ the data while doing so!

---
#### How it works
---

Using ```Asymmetric Encryption``` , ```secure_defaults``` creates an asymmetric key using one of the supported key types, and uses that key to encrypt your data using a symmetric encryption algorithm (for performance reasons, especially when working with blobs of data).

***Supports:***

```RSA Encryption```

```ECDSA Encryption```

```ECDSA Encryption with the Secure Enclave (if available)```

Leveraging ```Swift 4``` 's ```Codable``` protocol - create your object graph (all conforming to ```Codable```), have your root object conform to a ```PreferenceDomainType``` and ```secure_defaults``` handles the rest.

There is even a ```nuke()``` function to wipe out all the keys data (if you need to).

---
#### Usage:
---

Using ```secure_defaults``` is comprised of the following steps:

Step 1: Create your object conforming to ```PreferenceDomainType```, and call ```register()```

Step 2: Create a provider object, ```RSAEncryption``` / ```ECEncryption```

Step 3: Call the ```encrypt``` / ```decrypt``` functions

Step 4: Save your data using the ```save()``` function.

Here is an example:

```swift
import secure_defaults

class Prefs : Codable {
    
    var name : String = "Luke"
    var last = "Skywalker"
    var lastOpen = Date()
    var isUser = true
}

extension Prefs : PreferenceDomainType {
    static var key: String {
        return "settings"
    }
    
    static var name: String {
        return "Test Key Can Delete"
    }
    
    static var tag: String {
        return "preferences.com.tags"
    }
}

let p = Prefs()

///RSA Provider Encryption Example:
let provider = RSAEncryption<Prefs>()
do {
    let val = try provider.encrypt(input: p)
    p.save(encryptedPayload: val)
}
catch {
    print(error.localizedDescription)
}

var payload = Prefs.encryptedPayload()

do {
    let result = try provider.decrypt(input: payload)
    result.isUser //should be true
}
catch {
    print(error.localizedDescription)
}

```

That's it, you have just encrypted your app settings into a ```suite``` on the ```UserDefaults```!
