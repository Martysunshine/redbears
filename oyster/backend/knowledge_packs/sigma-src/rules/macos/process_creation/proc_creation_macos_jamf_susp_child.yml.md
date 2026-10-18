<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/macos/process_creation/proc_creation_macos_jamf_susp_child.yml -->
title: JAMF MDM Potential Suspicious Child Process
id: 2316929c-01aa-438c-970f-099145ab1ee6
status: test
description: Detects potential suspicious child processes of "jamf". Could be a sign of potential abuse of Jamf as a C2 server as seen by Typhon MythicAgent.
references:
    - https://github.com/MythicAgents/typhon/
    - https://www.zoocoup.org/casper/jamf_cheatsheet.pdf
    - https://docs.jamf.com/10.30.0/jamf-pro/administrator-guide/Components_Installed_on_Managed_Computers.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-08-22
tags:
    - attack.execution
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        ParentImage|endswith: '/jamf'
        Image|endswith:
            # Note: Add additional binaries/commands that are uncommon during your typical admin usage of Jamf
            - '/bash'
            - '/sh'
    condition: selection
falsepositives:
    - Legitimate execution of custom scripts or commands by Jamf administrators. Apply additional filters accordingly
level: medium
