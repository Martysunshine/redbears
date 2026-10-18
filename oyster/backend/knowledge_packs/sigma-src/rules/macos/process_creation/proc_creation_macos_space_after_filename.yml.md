<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/macos/process_creation/proc_creation_macos_space_after_filename.yml -->
title: Space After Filename - macOS
id: b6e2a2e3-2d30-43b1-a4ea-071e36595690
status: test
description: Detects attempts to masquerade as legitimate files by adding a space to the end of the filename.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1036.006/T1036.006.md
author: remotephone
date: 2021-11-20
modified: 2023-01-04
tags:
    - attack.stealth
    - attack.t1036.006
logsource:
    product: macos
    category: process_creation
detection:
    selection1:
        CommandLine|endswith: ' '
    selection2:
        Image|endswith: ' '
    condition: 1 of selection*
falsepositives:
    - Mistyped commands or legitimate binaries named to match the pattern
level: low
