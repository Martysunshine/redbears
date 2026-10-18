<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_sc_change_sevice_image_path_by_non_admin.yml -->
title: Possible Privilege Escalation via Weak Service Permissions
id: d937b75f-a665-4480-88a5-2f20e9f9b22a
status: test
description: Detection of sc.exe utility spawning by user with Medium integrity level to change service ImagePath or FailureCommand
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
    - https://pentestlab.blog/2017/03/30/weak-service-permissions/
author: Teymur Kheirkhabarov
date: 2019-10-26
modified: 2024-12-01
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.execution
    - attack.stealth
    - attack.t1574.011
logsource:
    category: process_creation
    product: windows
detection:
    scbynonadmin:
        Image|endswith: '\sc.exe'
        IntegrityLevel:
            - 'Medium'
            - 'S-1-16-8192'
    selection_binpath:
        CommandLine|contains|all:
            - 'config'
            - 'binPath'
    selection_failure:
        CommandLine|contains|all:
            - 'failure'
            - 'command'
    condition: scbynonadmin and 1 of selection_*
falsepositives:
    - Unknown
level: high
