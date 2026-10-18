<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/macos/process_creation/proc_creation_macos_csrutil_status.yml -->
title: System Integrity Protection (SIP) Enumeration
id: 53821412-17b0-4147-ade0-14faae67d54b
status: test
description: |
    Detects the use of csrutil to view the Configure System Integrity Protection (SIP) status. This technique is used in post-exploit scenarios.
references:
    - https://ss64.com/osx/csrutil.html
    - https://objective-see.org/blog/blog_0x6D.html
    - https://www.welivesecurity.com/2017/10/20/osx-proton-supply-chain-attack-elmedia/
    - https://www.virustotal.com/gui/file/05a2adb266ec6c0ba9ed176d87d8530e71e845348c13caf9f60049760c312cd3/behavior
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2024-01-02
tags:
    - attack.discovery
    - attack.t1518.001
logsource:
    product: macos
    category: process_creation
detection:
    # VT Query: behavior_processes:"csrutil status" p:5+ type:mac
    selection:
        Image|endswith: '/csrutil'
        CommandLine|contains: 'status'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: low
