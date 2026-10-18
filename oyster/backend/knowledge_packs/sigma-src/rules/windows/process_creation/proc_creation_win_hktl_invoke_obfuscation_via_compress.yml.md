<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_via_compress.yml -->
title: Invoke-Obfuscation COMPRESS OBFUSCATION
id: 7eedcc9d-9fdb-4d94-9c54-474e8affc0c7
status: test
description: Detects Obfuscated Powershell via COMPRESS OBFUSCATION
references:
    - https://github.com/SigmaHQ/sigma/issues/1009 # (Task 19)
author: Timur Zinniatullin, oscd.community
date: 2020-10-18
modified: 2022-12-29
tags:
    - attack.stealth
    - attack.t1027
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'new-object'
            - 'text.encoding]::ascii'
        CommandLine|contains:
            - 'system.io.compression.deflatestream'
            - 'system.io.streamreader'
            - 'readtoend('
    condition: selection
falsepositives:
    - Unknown
level: medium
