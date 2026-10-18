<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_uac_bypass_ntfs_reparse_point.yml -->
title: UAC Bypass Using NTFS Reparse Point - File
id: 7fff6773-2baa-46de-a24a-b6eec1aba2d1
status: test
description: Detects the pattern of UAC Bypass using NTFS reparse point and wusa.exe DLL hijacking (UACMe 36)
references:
    - https://github.com/hfiref0x/UACME
author: Christian Burkard (Nextron Systems)
date: 2021-08-30
modified: 2022-10-09
tags:
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|startswith: 'C:\Users\'
        TargetFilename|endswith: '\AppData\Local\Temp\api-ms-win-core-kernel32-legacy-l1.DLL'
    condition: selection
falsepositives:
    - Unknown
level: high
