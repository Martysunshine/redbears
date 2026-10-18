<!-- source: https://github.com/OWASP/mastg/blob/0e88142b5d7aad8f052b4e75199a8aad9b89d5b5/tools/generic/MASTG-TOOL-0134.md -->
---
title: cdxgen
platform: generic
source: https://github.com/CycloneDX/cdxgen
---

cdxgen can generate Software Bill of Materials (SBOM) for most applications and container images with a single command. It supports SwiftPM for iOS and Maven for Android. The generated SBOM can then be submitted to analysis tools such as @MASTG-TOOL-0132.

While the creation of an SBOM for a compiled Android app (APK or AAB) is supported, it is limited and mostly incomplete. This is mainly due to the removal of metadata from the libraries used in an app. Therefore, it is recommended to execute cdxgen in the Android app project folder to create a complete SBOM.
