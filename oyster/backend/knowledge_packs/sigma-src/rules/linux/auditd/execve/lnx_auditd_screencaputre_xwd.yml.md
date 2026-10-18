<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/auditd/execve/lnx_auditd_screencaputre_xwd.yml -->
title: Screen Capture with Xwd
id: e2f17c5d-b02a-442b-9052-6eb89c9fec9c
status: test
description: Detects adversary creating screen capture of a full with xwd. Highly recommended using rule on servers, due high usage of screenshot utilities on user workstations
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1113/T1113.md#atomic-test-3---x-windows-capture
    - https://linux.die.net/man/1/xwd
author: 'Pawel Mazur'
date: 2021-09-13
modified: 2022-12-18
tags:
    - attack.collection
    - attack.t1113
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: EXECVE
        a0: xwd
    xwd_root_window:
        a1: '-root'
        a2: '-out'
        a3|endswith: '.xwd'
    xwd_no_root_window:
        a1: '-out'
        a2|endswith: '.xwd'
    condition: selection and 1 of xwd_*
falsepositives:
    - Legitimate use of screenshot utility
level: low
