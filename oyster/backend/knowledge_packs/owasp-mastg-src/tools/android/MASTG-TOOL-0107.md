<!-- source: https://github.com/OWASP/mastg/blob/0e88142b5d7aad8f052b4e75199a8aad9b89d5b5/tools/android/MASTG-TOOL-0107.md -->
---
title: jnitrace
platform: android
source: https://github.com/chame1eon/jnitrace
hosts: [windows, linux, macOS]
---

jnitrace is a Frida based tool to trace use of the JNI API in Android apps.

Native libraries contained within Android Apps often make use of the JNI API to utilize the Android Runtime. Tracking those calls through manual reverse engineering can be a slow and painful process. jnitrace works as a dynamic analysis tracing tool similar to frida-trace or strace but for the JNI.

<img src="https://i.ibb.co/ZJ04cBB/jnitrace-1.png" style="width: 80%; border-radius: 5px; margin: 2em" />
