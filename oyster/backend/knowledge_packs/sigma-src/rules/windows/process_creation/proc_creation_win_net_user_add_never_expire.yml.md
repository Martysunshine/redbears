<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_net_user_add_never_expire.yml -->
title: New User Created Via Net.EXE With Never Expire Option
id: b9f0e6f5-09b4-4358-bae4-08408705bd5c
related:
    - id: cd219ff3-fa99-45d4-8380-a7d15116c6dc
      type: derived
status: test
description: Detects creation of local users via the net.exe command with the option "never expire"
references:
    - https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-12
modified: 2023-02-21
tags:
    - attack.persistence
    - attack.t1136.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\net.exe'
              - '\net1.exe'
        - OriginalFileName:
              - 'net.exe'
              - 'net1.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'user'
            - 'add'
            - 'expires:never'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: high
