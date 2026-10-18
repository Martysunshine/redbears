<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/macos/process_creation/proc_creation_macos_sysadminctl_add_user_to_admin_group.yml -->
title: User Added To Admin Group Via Sysadminctl
id: 652c098d-dc11-4ba6-8566-c20e89042f2b
related:
    - id: 0c1ffcf9-efa9-436e-ab68-23a9496ebf5b
      type: obsolete
status: test
description: Detects attempts to create and add an account to the admin group via "sysadminctl"
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md#atomic-test-3---create-local-account-with-admin-privileges-using-sysadminctl-utility---macos
    - https://ss64.com/osx/sysadminctl.html
author: Sohan G (D4rkCiph3r)
date: 2023-03-19
tags:
    - attack.persistence
    - attack.initial-access
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1078.003
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        # Creates and adds new user to admin group
        Image|endswith: '/sysadminctl'
        CommandLine|contains|all:
            - ' -addUser '
            - ' -admin '
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium
