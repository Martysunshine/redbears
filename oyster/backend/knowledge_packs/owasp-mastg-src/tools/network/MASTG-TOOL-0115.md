<!-- source: https://github.com/OWASP/mastg/blob/0e88142b5d7aad8f052b4e75199a8aad9b89d5b5/tools/network/MASTG-TOOL-0115.md -->
---
title: HTTP Toolkit
platform: network
source: https://httptoolkit.com
---

HTTP Toolkit is an open-source tool designed to intercept, analyze, and debug HTTPS traffic. The tool captures HTTP traffic from Android, iOS, web or desktop applications.

It comes in a (limited) free version and paid version with additional features. HTTP Toolkit allows to setup its CA certificate and disabling SSL pinning via Frida and is also able to intercept HTTP requests from Flutter. In the free version it is not possible to set an up-stream proxy to re-direct the HTTP traffic to a penetration testing tool like BurpSuite.

Instead of HTTP Toolkit, you can rely on the tools mentioned in @MASTG-TECH-0109.
