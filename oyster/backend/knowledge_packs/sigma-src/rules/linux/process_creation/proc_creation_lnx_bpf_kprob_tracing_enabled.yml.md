<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_bpf_kprob_tracing_enabled.yml -->
title: Enable BPF Kprobes Tracing
id: 7692f583-bd30-4008-8615-75dab3f08a99
status: test
description: Detects common command used to enable bpf kprobes tracing
references:
    - https://embracethered.com/blog/posts/2021/offensive-bpf-bpftrace/
    - https://bpftrace.org/
    - https://www.kernel.org/doc/html/v5.0/trace/kprobetrace.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-25
tags:
    - attack.execution
    - attack.stealth
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains|all:
            - 'echo 1 >'
            - '/sys/kernel/debug/tracing/events/kprobes/'
        CommandLine|contains:
            - '/myprobe/enable'
            - '/myretprobe/enable'
    condition: selection
falsepositives:
    - Unknown
level: medium
