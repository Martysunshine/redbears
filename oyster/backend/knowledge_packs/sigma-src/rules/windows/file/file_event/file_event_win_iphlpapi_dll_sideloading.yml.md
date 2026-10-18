<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_iphlpapi_dll_sideloading.yml -->
title: Malicious DLL File Dropped in the Teams or OneDrive Folder
id: 1908fcc1-1b92-4272-8214-0fbaf2fa5163
status: test
description: |
    Detects creation of a malicious DLL file in the location where the OneDrive or Team applications
    Upon execution of the Teams or OneDrive application, the dropped malicious DLL file ("iphlpapi.dll") is sideloaded
references:
    - https://blog.cyble.com/2022/07/27/targeted-attacks-being-carried-out-via-dll-sideloading/
author: frack113
date: 2022-08-12
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.execution
    - attack.stealth
    - attack.t1574.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains|all:
            - 'iphlpapi.dll'
            - '\AppData\Local\Microsoft'
    condition: selection
falsepositives:
    - Unknown
level: high
