<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_via_stdin.yml -->
title: Invoke-Obfuscation Via Stdin
id: 9c14c9fa-1a63-4a64-8e57-d19280559490
status: test
description: Detects Obfuscated Powershell via Stdin in Scripts
references:
    - https://github.com/SigmaHQ/sigma/issues/1009 # (Task28)
author: Nikita Nazarov, oscd.community
date: 2020-10-12
modified: 2026-03-16
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
        CommandLine|re: '(?i)(?:set).*&&\s?set.*(?:environment|invoke|\$\{?input).*&&.*"'
    condition: selection
falsepositives:
    - Unknown
level: high
