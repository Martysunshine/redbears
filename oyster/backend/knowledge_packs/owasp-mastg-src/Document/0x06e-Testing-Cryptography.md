<!-- source: https://github.com/OWASP/mastg/blob/0e88142b5d7aad8f052b4e75199a8aad9b89d5b5/Document/0x06e-Testing-Cryptography.md -->
---
masvs_category: MASVS-CRYPTO
platform: ios
---

# iOS Cryptographic APIs

## Overview

In the ["Mobile App Cryptography"](0x04g-Testing-Cryptography.md) chapter, we introduced general cryptography best practices and described typical issues that can occur when cryptography is used incorrectly. In this chapter, we'll go into more detail on iOS's cryptography APIs. We'll show how to identify usage of those APIs in the source code and how to interpret cryptographic configurations. When reviewing code, make sure to compare the cryptographic parameters used with the current best practices linked from this guide.

Apple provides libraries that include implementations of most common cryptographic algorithms. [Apple's Cryptographic Services Guide](https://developer.apple.com/library/content/documentation/Security/Conceptual/cryptoservices/GeneralPurposeCrypto/GeneralPurposeCrypto.html "Apple Cryptographic Services Guide") is a great reference. It contains generalized documentation of how to use standard libraries to initialize and use cryptographic primitives, information that is useful for source code analysis.
