<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/registry/registry_set/registry_set_comhijack_sdclt.yml -->
title: COM Hijack via Sdclt
id: 07743f65-7ec9-404a-a519-913db7118a8d
status: test
description: Detects changes to 'HKCU\Software\Classes\Folder\shell\open\command\DelegateExecute'
references:
    - http://blog.sevagas.com/?Yet-another-sdclt-UAC-bypass
    - https://www.exploit-db.com/exploits/47696
author: Omkar Gudhate
date: 2020-09-27
modified: 2023-09-28
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1546
    - attack.t1548
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Software\Classes\Folder\shell\open\command\DelegateExecute'
    condition: selection
falsepositives:
    - Unknown
level: high
