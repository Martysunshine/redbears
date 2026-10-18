<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_msiexec_web_install.yml -->
title: MsiExec Web Install
id: f7b5f842-a6af-4da5-9e95-e32478f3cd2f
related:
    - id: 8150732a-0c9d-4a99-82b9-9efb9b90c40c
      type: similar
status: test
description: Detects suspicious msiexec process starts with web addresses as parameter
references:
    - https://blog.trendmicro.com/trendlabs-security-intelligence/attack-using-windows-installer-msiexec-exe-leads-lokibot/
author: Florian Roth (Nextron Systems)
date: 2018-02-09
modified: 2022-01-07
tags:
    - attack.stealth
    - attack.t1218.007
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - ' msiexec'
            - '://'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium
