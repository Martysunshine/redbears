<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_uac_bypass_consent_comctl32.yml -->
title: UAC Bypass Using Consent and Comctl32 - File
id: 62ed5b55-f991-406a-85d9-e8e8fdf18789
status: test
description: Detects the pattern of UAC Bypass using consent.exe and comctl32.dll (UACMe 22)
references:
    - https://github.com/hfiref0x/UACME
author: Christian Burkard (Nextron Systems)
date: 2021-08-23
modified: 2022-10-09
tags:
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|startswith: 'C:\Windows\System32\consent.exe.@'
        TargetFilename|endswith: '\comctl32.dll'
    condition: selection
falsepositives:
    - Unknown
level: high
