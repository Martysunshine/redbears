<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_wmi_password_never_expire.yml -->
title: Password Set to Never Expire via WMI
id: 7864a175-3654-4824-9f0d-f0da18ab27c0
status: experimental
description: |
    Detects the use of wmic.exe to modify user account settings and explicitly disable password expiration.
references:
    - https://www.huntress.com/blog/the-unwanted-guest
author: "Daniel Koifman (KoifSec)"
date: 2025-07-30
tags:
    - attack.privilege-escalation
    - attack.execution
    - attack.persistence
    - attack.t1047
    - attack.t1098
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:   # Example command simulated:  wmic  useraccount where name='guest' set passwordexpires=false
        - Image|endswith: '\wmic.exe'
        - OriginalFileName: 'wmic.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'useraccount'
            - ' set '
            - 'passwordexpires'
            - 'false'
    condition: all of selection_*
falsepositives:
    - Legitimate administrative activity
level: medium
