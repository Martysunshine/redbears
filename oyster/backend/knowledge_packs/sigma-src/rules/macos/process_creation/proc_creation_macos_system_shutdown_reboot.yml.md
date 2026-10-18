<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/macos/process_creation/proc_creation_macos_system_shutdown_reboot.yml -->
title: System Shutdown/Reboot - MacOs
id: 40b1fbe2-18ea-4ee7-be47-0294285811de
status: test
description: Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1529/T1529.md
author: 'Igor Fits, Mikhail Larin, oscd.community'
date: 2020-10-19
modified: 2022-11-26
tags:
    - attack.impact
    - attack.t1529
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '/shutdown'
            - '/reboot'
            - '/halt'
    condition: selection
falsepositives:
    - Legitimate administrative activity
level: informational
