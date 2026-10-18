<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_rundll32_inline_vbs.yml -->
title: Suspicious Rundll32 Invoking Inline VBScript
id: 1cc50f3f-1fc8-4acf-b2e9-6f172e1fdebd
status: test
description: Detects suspicious process related to rundll32 based on command line that invokes inline VBScript as seen being used by UNC2452
references:
    - https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/
author: Florian Roth (Nextron Systems)
date: 2021-03-05
modified: 2022-10-09
tags:
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'rundll32.exe'
            - 'Execute'
            - 'RegRead'
            - 'window.close'
    condition: selection
falsepositives:
    - Unknown
level: high
