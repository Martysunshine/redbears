<!-- source: https://github.com/OWASP/mastg/blob/0e88142b5d7aad8f052b4e75199a8aad9b89d5b5/tools/android/MASTG-TOOL-0125.md -->
---
title: Apkleaks
platform: android
source: https://github.com/dwisiswant0/apkleaks
hosts: [windows, linux, macOS]
---

Apkleaks is an open-source utility designed for static analysis of Android APK files, with a primary focus on identifying sensitive data such as API keys, URLs, AWS S3 buckets, and Firebase URLs. This tool automates the process of string analysis, facilitating the detection of hardcoded secrets and potential security vulnerabilities.

It offers support for custom regular expression rules, enabling users to specify additional search criteria through a JSON configuration file [regexes.json](https://github.com/dwisiswant0/apkleaks/blob/master/config/regexes.json).
