<!-- source: https://github.com/OWASP/mastg/blob/d7fd7d45636ef9acbae89d0247e8dd748aa6918d/tests-beta/android/MASVS-STORAGE/MASTG-TEST-0304.md -->
---
title: References to Sensitive Data Unencrypted via Android Room Database 
platform: android
id: MASTG-TEST-0304
type: [static, code]
weakness: MASWE-0001
best-practices: []
profiles: [L1, L2]
knowledge: [MASTG-KNOW-0037]
status: placeholder
note: This test checks if the app uses the default SQLite API (e.g., `SQLiteOpenHelper`, `context.openOrCreateDatabase`) to store sensitive data (e.g., tokens, PII) in an unencrypted database file within the app's sandbox. It confirms the absence of secure alternatives like SQLCipher or encrypted databases.
---
