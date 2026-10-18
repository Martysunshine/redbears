<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_esxcli_permission_change_admin.yml -->
title: ESXi Admin Permission Assigned To Account Via ESXCLI
id: 9691f58d-92c1-4416-8bf3-2edd753ec9cf
status: test
description: Detects execution of the "esxcli" command with the "system" and "permission" flags in order to assign admin permissions to an account.
references:
    - https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_system.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-09-04
tags:
    - attack.persistence
    - attack.execution
    - attack.privilege-escalation
    - attack.t1059.012
    - attack.t1098
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/esxcli'
        CommandLine|contains: 'system'
        CommandLine|contains|all:
            - ' permission '
            - ' set'
            - 'Admin'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: high
