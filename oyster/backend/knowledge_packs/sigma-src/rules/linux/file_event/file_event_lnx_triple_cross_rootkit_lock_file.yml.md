<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/file_event/file_event_lnx_triple_cross_rootkit_lock_file.yml -->
title: Triple Cross eBPF Rootkit Default LockFile
id: c0239255-822c-4630-b7f1-35362bcb8f44
status: test
description: Detects the creation of the file "rootlog" which is used by the TripleCross rootkit as a way to check if the backdoor is already running.
references:
    - https://github.com/h3xduck/TripleCross/blob/1f1c3e0958af8ad9f6ebe10ab442e75de33e91de/src/helpers/execve_hijack.c#L33
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-05
modified: 2022-12-31
tags:
    - attack.stealth
logsource:
    product: linux
    category: file_event
detection:
    selection:
        TargetFilename: '/tmp/rootlog'
    condition: selection
falsepositives:
    - Unlikely
level: high
