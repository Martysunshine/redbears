<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/security/win_security_protected_storage_service_access.yml -->
title: Protected Storage Service Access
id: 45545954-4016-43c6-855e-eae8f1c369dc
status: test
description: Detects access to a protected_storage service over the network. Potential abuse of DPAPI to extract domain backup keys from Domain Controllers
references:
    - https://threathunterplaybook.com/hunts/windows/190620-DomainDPAPIBackupKeyExtraction/notebook.html
author: Roberto Rodriguez @Cyb3rWard0g
date: 2019-08-10
modified: 2021-11-27
tags:
    - attack.lateral-movement
    - attack.t1021.002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5145
        ShareName|contains: 'IPC'
        RelativeTargetName: 'protected_storage'
    condition: selection
falsepositives:
    - Unknown
level: high
