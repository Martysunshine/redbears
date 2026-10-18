<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/macos/process_creation/proc_creation_macos_jxa_in_memory_execution.yml -->
title: JXA In-memory Execution Via OSAScript
id: f1408a58-0e94-4165-b80a-da9f96cf6fc3
related:
    - id: 1bc2e6c5-0885-472b-bed6-be5ea8eace55
      type: derived
status: test
description: Detects possible malicious execution of JXA in-memory via OSAScript
references:
    - https://redcanary.com/blog/applescript/
author: Sohan G (D4rkCiph3r)
date: 2023-01-31
tags:
    - attack.t1059.002
    - attack.t1059.007
    - attack.execution
logsource:
    product: macos
    category: process_creation
detection:
    selection_main:
        CommandLine|contains|all:
            - 'osascript'
            - ' -e '
            - 'eval'
            - 'NSData.dataWithContentsOfURL'
    selection_js:
        - CommandLine|contains|all:
              - ' -l '
              - 'JavaScript'
        - CommandLine|contains: '.js'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
