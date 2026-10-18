<!-- source: https://github.com/MicrosoftDocs/windowsserverdocs/blob/2b6696197bc41e7d770c70ee354bdb49c6642697/WindowsServerDocs/identity/ad-fs/troubleshooting/ad-fs-tshoot-fiddler.md -->
---
title: AD FS Troubleshooting - Fiddler
description:  This document introduces the Fiddler tool, including guidance on installing and configuring Fiddler to troubleshoot AD FS claims issues
ms.date: 02/13/2024
ms.topic: troubleshooting-general
ms.custom: sfi-image-nochange
---

# AD FS Troubleshooting - Fiddler

Fiddler is a tool that can be used to capture HTTP/HTTPS web traffic. Fiddler can be used to assist in troubleshooting the claim issuance process. Capturing and examining HTTP/HTTPS web traffic can help you get a better understanding of where an interaction is breaking down. This article describes how to install and set up Fiddler to capture AD FS traffic. For an example Fiddler trace using WS-Federation, see [AD FS Troubleshooting - Fiddler - WS-Federation](ad-fs-tshoot-fiddler-ws-fed.md)

## Download and install Fiddler

See [Fiddler download](https://www.telerik.com/download/fiddler) to download the Fiddler tool. After you have downloaded Fiddler, proceed with installing it.

## Configure Fiddler to capture AD FS traffic

In order to capture AD FS traffic, you need to configure Fiddler to decrypt SSL traffic.

### Configure the Fiddler SSL certificate

 Use the following procedure to setup Fiddler to decrypt SSL traffic.

1. Open Fiddler
1. At the top, under **Tools**, select **Fiddler Options**.
1. Select the HTTPS tab.
1. Place a check in **Decrypt HTTPS traffic** and select **from browsers only** from the drop-down.
1. Place a check in **Ignore server certificate errors**.
1. Select **OK**.

![Fiddler](media/ad-fs-tshoot-fiddler/fiddler1.png)

## Related links

- [AD FS Troubleshooting](ad-fs-tshoot-overview.md)
