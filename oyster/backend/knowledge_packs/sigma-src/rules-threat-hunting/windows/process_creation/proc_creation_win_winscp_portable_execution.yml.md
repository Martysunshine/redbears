<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-threat-hunting/windows/process_creation/proc_creation_win_winscp_portable_execution.yml -->
title: Winscp Execution From Non Standard Folder
id: 7674f8ef-7141-4cf0-a311-ee359264c64c
status: experimental
description: Detects the execution of Winscp from an a non standard folder. This could indicate the execution of Winscp portable.
references:
    - https://blogs.blackberry.com/en/2024/07/akira-ransomware-targets-the-latam-airline-industry
author: frack113
date: 2025-10-12
tags:
    - attack.exfiltration
    - attack.t1048
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\WinSCP.exe'
        - OriginalFileName: 'winscp.exe'
    filter_main_location:
        Image|startswith: 'C:\Program Files (x86)\WinSCP\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
