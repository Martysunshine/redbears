<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_powershell_frombase64string_archive.yml -->
title: Suspicious FromBase64String Usage On Gzip Archive - Process Creation
id: d75d6b6b-adb9-48f7-824b-ac2e786efe1f
related:
    - id: df69cb1d-b891-4cd9-90c7-d617d90100ce
      type: similar
status: test
description: Detects attempts of decoding a base64 Gzip archive via PowerShell. This technique is often used as a method to load malicious content into memory afterward.
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=43
author: frack113
date: 2022-12-23
tags:
    - attack.command-and-control
    - attack.t1132.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'FromBase64String'
            - 'MemoryStream'
            - 'H4sI'
    condition: selection
falsepositives:
    - Legitimate administrative script
level: medium
