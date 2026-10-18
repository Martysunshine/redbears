<!-- source: https://github.com/OWASP/mastg/blob/0e88142b5d7aad8f052b4e75199a8aad9b89d5b5/knowledge/android/MASVS-CODE/MASTG-KNOW-0010.md -->
---
masvs_category: MASVS-CODE
platform: android
title: Exception Handling
---

Exceptions occur when an application gets into an abnormal or error state. Both Java and C++ may throw exceptions. Testing exception handling is about ensuring that the app will handle an exception and transition to a safe state without exposing sensitive information via the UI or the app's logging mechanisms.
