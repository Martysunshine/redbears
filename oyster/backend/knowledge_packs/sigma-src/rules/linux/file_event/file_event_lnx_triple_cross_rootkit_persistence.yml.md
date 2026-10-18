<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/file_event/file_event_lnx_triple_cross_rootkit_persistence.yml -->
title: Triple Cross eBPF Rootkit Default Persistence
id: 1a2ea919-d11d-4d1e-8535-06cda13be20f
status: test
description: Detects the creation of "ebpfbackdoor" files in both "cron.d" and "sudoers.d" directories. Which both are related to the TripleCross persistence method
references:
    - https://github.com/h3xduck/TripleCross/blob/12629558b8b0a27a5488a0b98f1ea7042e76f8ab/apps/deployer.sh
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-05
modified: 2022-12-31
tags:
    - attack.privilege-escalation
    - attack.execution
    - attack.persistence
    - attack.t1053.003
logsource:
    product: linux
    category: file_event
detection:
    selection:
        TargetFilename|endswith: 'ebpfbackdoor'
    condition: selection
falsepositives:
    - Unlikely
level: high
