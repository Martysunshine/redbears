<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/registry/registry_set/registry_set_fax_change_service_user.yml -->
title: Change User Account Associated with the FAX Service
id: e3fdf743-f05b-4051-990a-b66919be1743
status: test
description: Detect change of the user account associated with the FAX service to avoid the escalation problem.
references:
    - https://twitter.com/dottor_morte/status/1544652325570191361
    - https://raw.githubusercontent.com/RiccardoAncarani/talks/master/F-Secure/unorthodox-lateral-movement.pdf
author: frack113
date: 2022-07-17
modified: 2022-12-30
tags:
    - attack.persistence
    - attack.defense-impairment
    - attack.t1112
logsource:
    product: windows
    category: registry_set
detection:
    selection:
        TargetObject: HKLM\System\CurrentControlSet\Services\Fax\ObjectName
    filter:
        Details|contains: NetworkService
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
