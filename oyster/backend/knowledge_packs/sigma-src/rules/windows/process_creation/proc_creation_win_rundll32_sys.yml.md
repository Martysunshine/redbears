<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_rundll32_sys.yml -->
title: Suspicious Rundll32 Activity Invoking Sys File
id: 731231b9-0b5d-4219-94dd-abb6959aa7ea
status: test
description: Detects suspicious process related to rundll32 based on command line that includes a *.sys file as seen being used by UNC2452
references:
    - https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/
author: Florian Roth (Nextron Systems)
date: 2021-03-05
modified: 2022-10-09
tags:
    - attack.stealth
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains: 'rundll32.exe'
    selection2:
        CommandLine|contains:
            - '.sys,'
            - '.sys '
    condition: all of selection*
falsepositives:
    - Unknown
level: high
