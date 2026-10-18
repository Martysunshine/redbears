<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_chattr_immutable_removal.yml -->
title: Remove Immutable File Attribute
id: 34979410-e4b5-4e5d-8cfb-389fdff05c12
related:
    - id: a5b977d6-8a81-4475-91b9-49dbfcd941f7
      type: derived
status: test
description: Detects usage of the 'chattr' utility to remove immutable file attribute.
references:
    - https://www.trendmicro.com/en_us/research/22/i/how-malicious-actors-abuse-native-linux-tools-in-their-attacks.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-15
tags:
    - attack.defense-impairment
    - attack.t1222.002
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/chattr'
        CommandLine|contains: ' -i '
    condition: selection
falsepositives:
    - Administrator interacting with immutable files (e.g. for instance backups).
level: medium
