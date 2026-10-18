<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_triple_cross_rootkit_install.yml -->
title: Triple Cross eBPF Rootkit Install Commands
id: 22236d75-d5a0-4287-bf06-c93b1770860f
status: test
description: Detects default install commands of the Triple Cross eBPF rootkit based on the "deployer.sh" script
references:
    - https://github.com/h3xduck/TripleCross/blob/1f1c3e0958af8ad9f6ebe10ab442e75de33e91de/apps/deployer.sh
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-05
tags:
    - attack.stealth
    - attack.t1014
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/sudo'
        CommandLine|contains|all:
            - ' tc '
            - ' enp0s3 '
        CommandLine|contains:
            - ' qdisc '
            - ' filter '
    condition: selection
falsepositives:
    - Unlikely
level: high
