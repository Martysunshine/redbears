<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/auditd/execve/lnx_auditd_system_shutdown_reboot.yml -->
title: System Shutdown/Reboot - Linux
id: 4cb57c2f-1f29-41f8-893d-8bed8e1c1d2f
status: test
description: Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1529/T1529.md
author: 'Igor Fits, oscd.community'
date: 2020-10-15
modified: 2022-11-26
tags:
    - attack.impact
    - attack.t1529
logsource:
    product: linux
    service: auditd
detection:
    execve:
        type: 'EXECVE'
    shutdowncmd:
        - 'shutdown'
        - 'reboot'
        - 'halt'
        - 'poweroff'
    init:
        - 'init'
        - 'telinit'
    initselection:
        - 0
        - 6
    condition: execve and (shutdowncmd or (init and initselection))
falsepositives:
    - Legitimate administrative activity
level: informational
