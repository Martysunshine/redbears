<!-- source: https://github.com/OWASP/mastg/blob/0e88142b5d7aad8f052b4e75199a8aad9b89d5b5/techniques/android/MASTG-TECH-0115.md -->
---
title: Obtaining Compiler-Provided Security Features
platform: android
---

Run @MASTG-TOOL-0129 on the target binary, for example a shared library and grep for the keywords you'd like to check for.

```sh
rabin2 -I lib/x86_64/libnative-lib.so | grep -E "canary|pic"
canary   false
```
