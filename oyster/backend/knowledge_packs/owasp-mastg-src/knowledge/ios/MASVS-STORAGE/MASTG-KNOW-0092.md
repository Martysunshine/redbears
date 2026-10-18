<!-- source: https://github.com/OWASP/mastg/blob/0e88142b5d7aad8f052b4e75199a8aad9b89d5b5/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0092.md -->
---
masvs_category: MASVS-STORAGE
platform: ios
title: Binary Data Storage
---

`NSData` (static data objects) and `NSMutableData` (dynamic data objects) are typically used for data storage, but they are also useful for distributed objects applications, in which data contained in data objects can be copied or moved between applications.

When writing `NSData` objects using [`write(to:options:)`](https://developer.apple.com/documentation/Foundation/Data/write(to:options:)), you can specify [`WritingOptions`](https://developer.apple.com/documentation/foundation/nsdata/writingoptions) for file protection:

- `noFileProtection`: does not encrypt the file.
- `completeFileProtection`: ensures the file is encrypted and can only be accessed when the device is unlocked.
- `completeFileProtectionUnlessOpen`: ensures the file is encrypted and can only be accessed when the device is unlocked or the file is already open.
- `completeFileProtectionUntilFirstUserAuthentication`: ensures the file is encrypted and can only be accessed until the first user authentication after a reboot.
