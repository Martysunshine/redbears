<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_renamed_vmnat.yml -->
title: Renamed Vmnat.exe Execution
id: 7b4f794b-590a-4ad4-ba18-7964a2832205
status: test
description: Detects renamed vmnat.exe or portable version that can be used for DLL side-loading
references:
    - https://twitter.com/malmoeb/status/1525901219247845376
author: elhoim
date: 2022-09-09
modified: 2023-02-03
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.execution
    - attack.stealth
    - attack.t1574.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: 'vmnat.exe'
    filter_rename:
        Image|endswith: 'vmnat.exe'
    condition: selection and not 1 of filter_*
falsepositives:
    - Unknown
level: high
