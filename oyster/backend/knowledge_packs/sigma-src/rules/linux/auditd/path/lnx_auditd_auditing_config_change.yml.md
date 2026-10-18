<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/auditd/path/lnx_auditd_auditing_config_change.yml -->
title: Auditing Configuration Changes on Linux Host
id: 977ef627-4539-4875-adf4-ed8f780c4922
status: test
description: Detect changes in auditd configuration files
references:
    - https://github.com/Neo23x0/auditd/blob/master/audit.rules
    - Self Experience
author: Mikhail Larin, oscd.community
date: 2019-10-25
modified: 2021-11-27
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: PATH
        name:
            - /etc/audit/*
            - /etc/libaudit.conf
            - /etc/audisp/*
    condition: selection
falsepositives:
    - Legitimate administrative activity
level: high
