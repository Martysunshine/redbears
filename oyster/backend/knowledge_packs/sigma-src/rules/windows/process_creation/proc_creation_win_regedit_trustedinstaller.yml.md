<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_regedit_trustedinstaller.yml -->
title: Regedit as Trusted Installer
id: 883835a7-df45-43e4-bf1d-4268768afda4
status: test
description: Detects a regedit started with TrustedInstaller privileges or by ProcessHacker.exe
references:
    - https://twitter.com/1kwpeter/status/1397816101455765504
author: Florian Roth (Nextron Systems)
date: 2021-05-27
modified: 2022-10-09
tags:
    - attack.privilege-escalation
    - attack.t1548
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\regedit.exe'
        ParentImage|endswith:
            - '\TrustedInstaller.exe'
            - '\ProcessHacker.exe'
    condition: selection
falsepositives:
    - Unlikely
level: high
