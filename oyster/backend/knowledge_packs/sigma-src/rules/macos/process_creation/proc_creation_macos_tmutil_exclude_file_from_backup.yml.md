<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/macos/process_creation/proc_creation_macos_tmutil_exclude_file_from_backup.yml -->
title: New File Exclusion Added To Time Machine Via Tmutil - MacOS
id: 9acf45ed-3a26-4062-bf08-56857613eb52
status: test
description: |
    Detects the addition of a new file or path exclusion to MacOS Time Machine via the "tmutil" utility.
    An adversary could exclude a path from Time Machine backups to prevent certain files from being backed up.
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
        CommandLine|contains: 'addexclusion'
    condition: all of selection_*
falsepositives:
    - Legitimate administrator activity
level: medium
