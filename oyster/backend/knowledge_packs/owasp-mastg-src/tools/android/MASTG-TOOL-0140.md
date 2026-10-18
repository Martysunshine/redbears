<!-- source: https://github.com/OWASP/mastg/blob/0e88142b5d7aad8f052b4e75199a8aad9b89d5b5/tools/android/MASTG-TOOL-0140.md -->
---
title: frida-multiple-unpinning
platform: android
source: https://codeshare.frida.re/@akabe1/frida-multiple-unpinning
---

Frida-multiple unpinning is a Frida CodeShare script to bypass various forms of TLS pinning. This is one of the most extensive TLS pinning bypass scripts available on CodeShare. One of its main strengths is a dynamic bypass which detects instantiations of the `SSLPeerUnverifiedException` class and automatically patches the method responsible for throwing the exception.

You can run the script directly with Frida:

```bash
$ frida -U --codeshare akabe1/frida-multiple-unpinning -f YOUR_BINARY
```
