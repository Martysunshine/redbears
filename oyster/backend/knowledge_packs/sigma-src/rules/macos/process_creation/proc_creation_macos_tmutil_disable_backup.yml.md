<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/macos/process_creation/proc_creation_macos_tmutil_disable_backup.yml -->
title: Time Machine Backup Disabled Via Tmutil - MacOS
id: 2c95fa8a-8b8d-4787-afce-7117ceb8e3da
status: test
description: |
    Detects disabling of Time Machine (Apple's automated backup utility software) via the native macOS backup utility "tmutil".
    An attacker can use this to prevent backups from occurring.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md#atomic-test-12---disable-time-machine
    - https://www.loobins.io/binaries/tmutil/
author: Pratinav Chandra
date: 2024-05-29
tags:
    - attack.impact
    - attack.t1490
logsource:
    category: process_creation
    product: macos
detection:
    selection_img:
        - Image|endswith: '/tmutil'
        - CommandLine|contains: 'tmutil'
    selection_cmd:
        CommandLine|contains: 'disable'
    condition: all of selection_*
falsepositives:
    - Legitimate administrator activity
level: medium
