<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_lolbin_diantz_ads.yml -->
title: Suspicious Diantz Alternate Data Stream Execution
id: 6b369ced-4b1d-48f1-b427-fdc0de0790bd
status: test
description: Compress target file into a cab file stored in the Alternate Data Stream (ADS) of the target file.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Diantz/
author: frack113
date: 2021-11-26
modified: 2022-12-31
tags:
    - attack.stealth
    - attack.t1564.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - diantz.exe
            - .cab
        CommandLine|re: ':[^\\]'
    condition: selection
falsepositives:
    - Very Possible
level: medium
