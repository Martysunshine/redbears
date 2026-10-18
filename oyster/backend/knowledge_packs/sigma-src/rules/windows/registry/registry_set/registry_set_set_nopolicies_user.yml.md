<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/registry/registry_set/registry_set_set_nopolicies_user.yml -->
title: Registry Explorer Policy Modification
id: 1c3121ed-041b-4d97-a075-07f54f20fb4a
status: test
description: Detects registry modifications that disable internal tools or functions in explorer (malware like Agent Tesla uses this technique)
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md
author: frack113
date: 2022-03-18
modified: 2023-08-17
tags:
    - attack.persistence
    - attack.defense-impairment
    - attack.t1112
logsource:
    category: registry_set
    product: windows
detection:
    selection_set_1:
        TargetObject|endswith:
            - 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoLogOff'
            - 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDesktop'
            - 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoRun'
            - 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoFind'
            - 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoControlPanel'
            - 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoFileMenu'
            - 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoClose'
            - 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoSetTaskbar'
            - 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoPropertiesMyDocuments'
            - 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoTrayContextMenu'
        Details: 'DWORD (0x00000001)'
    condition: selection_set_1
falsepositives:
    - Legitimate admin script
level: medium
