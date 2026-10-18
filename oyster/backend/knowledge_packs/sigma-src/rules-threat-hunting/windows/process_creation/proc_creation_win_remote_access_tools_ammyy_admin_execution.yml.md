<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-threat-hunting/windows/process_creation/proc_creation_win_remote_access_tools_ammyy_admin_execution.yml -->
title: Remote Access Tool - Ammy Admin Agent Execution
id: 7da7809e-f3d5-47a3-9d5d-fc9d019caf14
status: test
description: Detects the execution of the Ammy Admin RMM agent for remote management.
references:
    - https://www.ammyy.com/en/admin_features.html
author: '@kostastsale'
date: 2024-08-05
tags:
    - attack.execution
    - attack.persistence
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\rundll32.exe'
        CommandLine|contains: 'AMMYY\aa_nts.dll",run'
    condition: selection
falsepositives:
    - Legitimate use of Ammy Admin RMM agent for remote management by admins.
level: medium
