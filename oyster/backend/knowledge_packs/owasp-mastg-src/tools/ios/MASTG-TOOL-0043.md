<!-- source: https://github.com/OWASP/mastg/blob/0e88142b5d7aad8f052b4e75199a8aad9b89d5b5/tools/ios/MASTG-TOOL-0043.md -->
---
title: class-dump
platform: ios
source: https://github.com/nygard/class-dump
---

class-dump is a command line utility for examining the Objective-C runtime information stored in Mach-O (Mach object) files. It generates declarations for the classes, categories, and protocols.

The official release of the tool only works in macOS, but an unofficial [dockerized version](https://github.com/lucacapacci/class-dump-docker) is also available, allowing for use across different environments.
