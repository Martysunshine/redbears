<!-- source: https://github.com/OWASP/mastg/blob/d7fd7d45636ef9acbae89d0247e8dd748aa6918d/tests-beta/android/MASVS-STORAGE/MASTG-TEST-0306.md -->
---
title: References to Sensitive Data Stored Unencrypted via Android Room DB 
platform: android
id: MASTG-TEST-0306
type: [static, code]
weakness: MASWE-0001
best-practices: []
profiles: [L1, L2]
status: placeholder
note: This test checks if the app uses the Android Room Persistence Library to store sensitive data (e.g., tokens, PII) without integrating an encryption layer (e.g., SQLCipher). It confirms the database file is stored in plaintext within the app's private sandbox.
---
