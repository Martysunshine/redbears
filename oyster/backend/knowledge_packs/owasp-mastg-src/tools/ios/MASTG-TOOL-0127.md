<!-- source: https://github.com/OWASP/mastg/blob/0e88142b5d7aad8f052b4e75199a8aad9b89d5b5/tools/ios/MASTG-TOOL-0127.md -->
---
title: AppSync Unified
platform: ios
hosts: [ios]
source: https://github.com/akemin-dayo/AppSync
---

AppSync Unified disables various IPA signature verifications on jailbroken iOS devices, allowing you to install IPA files with missing or incorrect signatures. AppSync Unified does not require any configuration after installation and does not offer a direct way to install IPA files either.

!!! warning

    You can normally install AppSync Unified from the `https://cydia.akemi.ai/` repository by adding it to the package manager on your iOS device. However, as this repository is not always available, you can alternatively download the .deb file from the [releases page](https://github.com/akemin-dayo/AppSync/releases/) and install it using `dpkg -i` on the device.
