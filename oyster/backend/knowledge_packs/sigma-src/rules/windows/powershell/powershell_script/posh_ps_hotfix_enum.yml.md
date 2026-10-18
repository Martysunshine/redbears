<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/powershell/powershell_script/posh_ps_hotfix_enum.yml -->
title: PowerShell Hotfix Enumeration
id: f5d1def8-1de0-4a0e-9794-1f6f27dd605c
status: test
description: Detects call to "Win32_QuickFixEngineering" in order to enumerate installed hotfixes often used in "enum" scripts by attackers
references:
    - https://github.com/411Hall/JAWS/blob/233f142fcb1488172aa74228a666f6b3c5c48f1d/jaws-enum.ps1
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-21
tags:
    - attack.discovery
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'Win32_QuickFixEngineering'
            - 'HotFixID'
    condition: selection
falsepositives:
    - Legitimate administration scripts
level: medium
