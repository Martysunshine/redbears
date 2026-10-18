<!-- source: https://github.com/OWASP/mastg/blob/0e88142b5d7aad8f052b4e75199a8aad9b89d5b5/best-practices/MASTG-BEST-0009.md -->
---
title: Use Secure Encryption Algorithms
alias: use-secure-encryption-algorithms
id: MASTG-BEST-0009
platform: android
---

Replace insecure encryption algorithms with secure ones such as AES-256 (preferably in GCM mode) or Chacha20.

For comprehensive guidance on implementing secure encryption in Android, refer to the documentation on ["Cryptography"](https://developer.android.com/privacy-and-security/cryptography) and ["Broken or risky cryptographic algorithm"](https://developer.android.com/privacy-and-security/risks/broken-cryptographic-algorithm#weak-or-broken-cryptographic-encryption-functions-use-strong-cryptographic-algorithms-in-encryption-1B2M2Y8Asg) on the official Android Developers website.
