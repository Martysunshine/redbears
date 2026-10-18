<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/create_remote_thread/create_remote_thread_win_ttdinjec.yml -->
title: Remote Thread Creation Ttdinject.exe Proxy
id: c15e99a3-c474-48ab-b9a7-84549a7a9d16
status: test
description: Detects a remote thread creation of Ttdinject.exe used as proxy
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Ttdinject/
author: frack113
date: 2022-05-16
modified: 2022-06-02
tags:
    - attack.execution
    - attack.stealth
    - attack.t1127
logsource:
    product: windows
    category: create_remote_thread
detection:
    selection:
        SourceImage|endswith: '\ttdinject.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
