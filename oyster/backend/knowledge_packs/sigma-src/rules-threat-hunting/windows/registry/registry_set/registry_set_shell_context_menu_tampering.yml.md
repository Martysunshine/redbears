<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-threat-hunting/windows/registry/registry_set/registry_set_shell_context_menu_tampering.yml -->
title: Shell Context Menu Command Tampering
id: 868df2d1-0939-4562-83a7-27408c4a1ada
status: test
description: Detects changes to shell context menu commands. Use this rule to hunt for potential anomalies and suspicious shell commands.
references:
    - https://mrd0x.com/sentinelone-persistence-via-menu-context/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2024-03-06
tags:
    - attack.persistence
    - detection.threat-hunting
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains|all:
            - '\Software\Classes\'
            - '\shell\'
            - '\command\'
    condition: selection
falsepositives:
    - Likely from new software installation suggesting to add context menu items. Such as "PowerShell", "Everything", "Git", etc.
level: low
