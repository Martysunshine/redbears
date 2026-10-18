<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/macos/process_creation/proc_creation_macos_osacompile_runonly_execution.yml -->
title: OSACompile Run-Only Execution
id: b9d9b652-d8ed-4697-89a2-a1186ee680ac
status: test
description: Detects potential suspicious run-only executions compiled using OSACompile
references:
    - https://redcanary.com/blog/applescript/
    - https://ss64.com/osx/osacompile.html
author: Sohan G (D4rkCiph3r)
date: 2023-01-31
tags:
    - attack.t1059.002
    - attack.execution
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'osacompile'
            - ' -x '
            - ' -e '
    condition: selection
falsepositives:
    - Unknown
level: high
