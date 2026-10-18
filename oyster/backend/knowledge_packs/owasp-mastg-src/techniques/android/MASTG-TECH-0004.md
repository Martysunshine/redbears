<!-- source: https://github.com/OWASP/mastg/blob/0e88142b5d7aad8f052b4e75199a8aad9b89d5b5/techniques/android/MASTG-TECH-0004.md -->
---
title: Repackaging Apps
platform: android
---

If you need to test on a non-jailbroken device, you should learn how to repackage an app to enable dynamic testing on it.

Use a computer to perform all the steps indicated in the article ["Patching Android Applications"](https://github.com/sensepost/objection/wiki/Patching-Android-Applications) from the objection Wiki. Once you're done, you'll be able to patch an APK by calling the objection command:

```bash
objection patchapk --source app-release.apk
```

The patched application then needs to be installed using @MASTG-TOOL-0004.

> This repackaging method is enough for most use cases. For more advanced repackaging, refer to @MASTG-TECH-0039.
