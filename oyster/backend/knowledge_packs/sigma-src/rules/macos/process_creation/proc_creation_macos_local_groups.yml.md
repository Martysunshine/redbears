<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/macos/process_creation/proc_creation_macos_local_groups.yml -->
title: Local Groups Discovery - MacOs
id: 89bb1f97-c7b9-40e8-b52b-7d6afbd67276
status: test
description: Detects enumeration of local system groups
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1069.001/T1069.001.md
author: Ömer Günal, Alejandro Ortuno, oscd.community
date: 2020-10-11
modified: 2022-11-27
tags:
    - attack.discovery
    - attack.t1069.001
logsource:
    category: process_creation
    product: macos
detection:
    selection_1:
        Image|endswith: '/dscacheutil'
        CommandLine|contains|all:
            - '-q'
            - 'group'
    selection_2:
        Image|endswith: '/cat'
        CommandLine|contains: '/etc/group'
    selection_3:
        Image|endswith: '/dscl'
        CommandLine|contains|all:
            - '-list'
            - '/groups'
    condition: 1 of selection*
falsepositives:
    - Legitimate administration activities
level: informational
