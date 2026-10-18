<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_bpftrace_unsafe_option_usage.yml -->
title: BPFtrace Unsafe Option Usage
id: f8341cb2-ee25-43fa-a975-d8a5a9714b39
status: test
description: Detects the usage of the unsafe bpftrace option
references:
    - https://embracethered.com/blog/posts/2021/offensive-bpf-bpftrace/
    - https://bpftrace.org/
author: Andreas Hunkeler (@Karneades)
date: 2022-02-11
tags:
    - attack.execution
    - attack.t1059.004
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: 'bpftrace'
        CommandLine|contains: '--unsafe'
    condition: selection
falsepositives:
    - Legitimate usage of the unsafe option
level: medium
