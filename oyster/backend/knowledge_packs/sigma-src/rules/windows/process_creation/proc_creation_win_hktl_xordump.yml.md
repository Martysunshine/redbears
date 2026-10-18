<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_hktl_xordump.yml -->
title: HackTool - XORDump Execution
id: 66e563f9-1cbd-4a22-a957-d8b7c0f44372
status: test
description: Detects suspicious use of XORDump process memory dumping utility
references:
    - https://github.com/audibleblink/xordump
author: Florian Roth (Nextron Systems)
date: 2022-01-28
modified: 2023-02-08
tags:
    - attack.stealth
    - attack.t1036
    - attack.t1003.001
    - attack.credential-access
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\xordump.exe'
        - CommandLine|contains:
              - ' -process lsass.exe '
              - ' -m comsvcs '
              - ' -m dbghelp '
              - ' -m dbgcore '
    condition: selection
falsepositives:
    - Another tool that uses the command line switches of XORdump
level: high
