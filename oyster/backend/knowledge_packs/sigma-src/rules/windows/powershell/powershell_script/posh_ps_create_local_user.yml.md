<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/powershell/powershell_script/posh_ps_create_local_user.yml -->
title: PowerShell Create Local User
id: 243de76f-4725-4f2e-8225-a8a69b15ad61
status: test
description: Detects creation of a local user via PowerShell
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1136.001/T1136.001.md
author: '@ROxPinTeddy'
date: 2020-04-11
modified: 2022-12-25
tags:
    - attack.execution
    - attack.t1059.001
    - attack.persistence
    - attack.t1136.001
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains: 'New-LocalUser'
    condition: selection
falsepositives:
    - Legitimate user creation
level: medium
