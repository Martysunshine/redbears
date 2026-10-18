<!-- source: https://github.com/OWASP/mastg/blob/d7fd7d45636ef9acbae89d0247e8dd748aa6918d/tests-beta/android/MASVS-NETWORK/MASTG-TEST-0237.md -->
---
title: Cross-Platform Framework Configurations Allowing Cleartext Traffic
platform: android
id: MASTG-TEST-0237
type: [static, code]
weakness: MASWE-0026
status: placeholder
note: Cross-platform frameworks (e.g. Flutter, React native, ...), typically have their own implementations for HTTP libraries, where cleartext traffic can be allowed.
profiles: [L1, L2]
---
