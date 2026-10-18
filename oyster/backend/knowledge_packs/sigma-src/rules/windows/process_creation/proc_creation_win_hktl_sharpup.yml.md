<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_hktl_sharpup.yml -->
title: HackTool - SharpUp PrivEsc Tool Execution
id: c484e533-ee16-4a93-b6ac-f0ea4868b2f1
status: test
description: Detects the use of SharpUp, a tool for local privilege escalation
references:
    - https://github.com/GhostPack/SharpUp
author: Florian Roth (Nextron Systems)
date: 2022-08-20
modified: 2023-02-13
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.discovery
    - attack.execution
    - attack.stealth
    - attack.t1615
    - attack.t1569.002
    - attack.t1574.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\SharpUp.exe'
        - Description: 'SharpUp'
        - CommandLine|contains:
              - 'HijackablePaths'
              - 'UnquotedServicePath'
              - 'ProcessDLLHijack'
              - 'ModifiableServiceBinaries'
              - 'ModifiableScheduledTask'
              - 'DomainGPPPassword'
              - 'CachedGPPPassword'
    condition: selection
falsepositives:
    - Unknown
level: critical
