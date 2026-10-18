<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/security/win_security_net_share_obj_susp_desktop_ini.yml -->
title: Windows Network Access Suspicious desktop.ini Action
id: 35bc7e28-ee6b-492f-ab04-da58fcf6402e
status: test
description: Detects unusual processes accessing desktop.ini remotely over network share, which can be leveraged to alter how Explorer displays a folder's content (i.e. renaming files) without changing them on disk.
references:
    - https://isc.sans.edu/forums/diary/Desktopini+as+a+postexploitation+tool/25912/
author: Tim Shelton (HAWK.IO)
date: 2021-12-06
modified: 2022-01-16
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.t1547.009
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5145
        ObjectType: File
        RelativeTargetName|endswith: '\desktop.ini'
        AccessList|contains:
            - 'WriteData'
            - 'DELETE'
            - 'WriteDAC'
            - 'AppendData'
            - 'AddSubdirectory'
    condition: selection
falsepositives:
    - Read only access list authority
level: medium
