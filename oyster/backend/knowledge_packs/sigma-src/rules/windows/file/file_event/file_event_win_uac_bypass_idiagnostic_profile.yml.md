<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_uac_bypass_idiagnostic_profile.yml -->
title: UAC Bypass Using IDiagnostic Profile - File
id: 48ea844d-19b1-4642-944e-fe39c2cc1fec
status: test
description: Detects the creation of a file by "dllhost.exe" in System32 directory part of "IDiagnosticProfileUAC" UAC bypass technique
references:
    - https://github.com/Wh04m1001/IDiagnosticProfileUAC
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-03
tags:
    - attack.execution
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    product: windows
    category: file_event
detection:
    selection:
        Image|endswith: '\DllHost.exe'
        TargetFilename|startswith: 'C:\Windows\System32\'
        TargetFilename|endswith: '.dll'
    condition: selection
falsepositives:
    - Unknown
level: high
