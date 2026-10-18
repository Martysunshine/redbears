<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/macos/process_creation/proc_creation_macos_susp_system_network_discovery.yml -->
title: System Network Discovery - macOS
id: 58800443-f9fc-4d55-ae0c-98a3966dfb97
status: test
description: Detects enumeration of local network configuration
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1016/T1016.md
author: remotephone, oscd.community
date: 2020-10-06
modified: 2024-08-29
tags:
    - attack.discovery
    - attack.t1016
logsource:
    product: macos
    category: process_creation
detection:
    selection_1:
        Image|endswith:
            - '/arp'
            - '/ifconfig'
            - '/netstat'
            - '/networksetup'
            - '/socketfilterfw'
    selection_2:
        Image: '/usr/bin/defaults'
        CommandLine|contains|all:
            - '/Library/Preferences/com.apple.alf'
            - 'read'
    filter_main_wifivelocityd:
        ParentImage|endswith: '/wifivelocityd'
    condition: 1 of selection_* and not 1 of filter_main_*
falsepositives:
    - Legitimate administration activities
level: informational
