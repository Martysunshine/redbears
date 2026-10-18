<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/macos/process_creation/proc_creation_macos_split_file_into_pieces.yml -->
title: Split A File Into Pieces
id: 7f2bb9d5-6395-4de5-969c-70c11fbe6b12
status: test
description: Detection use of the command "split" to split files into parts and possible transfer.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1030/T1030.md
author: 'Igor Fits, Mikhail Larin, oscd.community'
date: 2020-10-15
modified: 2021-11-27
tags:
    - attack.exfiltration
    - attack.t1030
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        Image|endswith: '/split'
    condition: selection
falsepositives:
    - Legitimate administrative activity
level: low
