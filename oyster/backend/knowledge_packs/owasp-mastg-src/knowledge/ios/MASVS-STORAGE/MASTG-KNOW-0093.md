<!-- source: https://github.com/OWASP/mastg/blob/0e88142b5d7aad8f052b4e75199a8aad9b89d5b5/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0093.md -->
---
masvs_category: MASVS-STORAGE
platform: ios
title: UserDefaults
---

The [`UserDefaults`](https://developer.apple.com/documentation/foundation/userdefaults "UserDefaults Class") class, part of the Foundation Framework, provides a programmatic interface for storing key-value pairs across app launches. It stores data in a plist file within the app sandbox and is intended for small, non-sensitive data.

`UserDefaults` supports common types like `NSData`, `NSString`, `NSNumber`, `NSDate`, and `NSArray`. Other types must be converted to `NSData`.

Data is stored locally and included in device backups, except on managed educational devices.
