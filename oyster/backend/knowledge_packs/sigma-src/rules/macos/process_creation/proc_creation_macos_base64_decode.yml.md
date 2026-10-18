<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/macos/process_creation/proc_creation_macos_base64_decode.yml -->
title: Decode Base64 Encoded Text -MacOs
id: 719c22d7-c11a-4f2c-93a6-2cfdd5412f68
status: test
description: Detects usage of base64 utility to decode arbitrary base64-encoded text
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1027/T1027.md
author: Daniil Yugoslavskiy, oscd.community
date: 2020-10-19
modified: 2022-11-26
tags:
    - attack.stealth
    - attack.t1027
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image: '/usr/bin/base64'
        CommandLine|contains: '-d'
    condition: selection
falsepositives:
    - Legitimate activities
level: low
