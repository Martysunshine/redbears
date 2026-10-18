<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_lolbin_diantz_remote_cab.yml -->
title: Suspicious Diantz Download and Compress Into a CAB File
id: 185d7418-f250-42d0-b72e-0c8b70661e93
status: test
description: Download and compress a remote file and store it in a cab file on local machine.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Diantz/
author: frack113
date: 2021-11-26
modified: 2022-08-13
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - diantz.exe
            - ' \\\\'
            - '.cab'
    condition: selection
falsepositives:
    - Unknown
level: medium
