<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/builtin/lnx_potential_susp_ebpf_activity.yml -->
title: Potential Suspicious BPF Activity - Linux
id: 0fadd880-6af3-4610-b1e5-008dc3a11b8a
status: test
description: Detects the presence of "bpf_probe_write_user" BPF helper-generated warning messages. Which could be a sign of suspicious eBPF activity on the system.
references:
    - https://redcanary.com/blog/ebpf-malware/
    - https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
author: Red Canary (idea), Nasreddine Bencherchali
date: 2023-01-25
tags:
    - attack.persistence
    - attack.stealth
logsource:
    product: linux
detection:
    selection:
        - 'bpf_probe_write_user'
    condition: selection
falsepositives:
    - Unknown
level: high
