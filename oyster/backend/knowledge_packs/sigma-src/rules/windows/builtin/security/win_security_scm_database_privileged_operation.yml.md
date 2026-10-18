<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/security/win_security_scm_database_privileged_operation.yml -->
title: SCM Database Privileged Operation
id: dae8171c-5ec6-4396-b210-8466585b53e9
status: test
description: Detects non-system users performing privileged operation os the SCM database
references:
    - https://threathunterplaybook.com/hunts/windows/190826-RemoteSCMHandle/notebook.html
author: Roberto Rodriguez @Cyb3rWard0g, Tim Shelton
date: 2019-08-15
modified: 2022-09-18
tags:
    - attack.privilege-escalation
    - attack.t1548
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4674
        ObjectType: 'SC_MANAGER OBJECT'
        ObjectName: 'servicesactive'
        PrivilegeList: 'SeTakeOwnershipPrivilege'
    filter:
        SubjectLogonId: '0x3e4'
        ProcessName|endswith: ':\Windows\System32\services.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium
