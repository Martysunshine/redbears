<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_splwow64_cli_anomaly.yml -->
title: Suspicious Splwow64 Without Params
id: 1f1a8509-2cbb-44f5-8751-8e1571518ce2
status: test
description: Detects suspicious Splwow64.exe process without any command line parameters
references:
    - https://twitter.com/sbousseaden/status/1429401053229891590?s=12
author: Florian Roth (Nextron Systems)
date: 2021-08-23
modified: 2022-12-25
tags:
    - attack.stealth
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\splwow64.exe'
        CommandLine|endswith: 'splwow64.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
