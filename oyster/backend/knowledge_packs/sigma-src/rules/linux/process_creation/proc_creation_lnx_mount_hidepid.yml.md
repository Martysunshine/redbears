<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_mount_hidepid.yml -->
title: Mount Execution With Hidepid Parameter
id: ec52985a-d024-41e3-8ff6-14169039a0b3
status: test
description: Detects execution of the "mount" command with "hidepid" parameter to make invisible processes to other users from the system
references:
    - https://blogs.blackberry.com/
    - https://www.cyberciti.biz/faq/linux-hide-processes-from-other-users/
    - https://twitter.com/Joseliyo_Jstnk/status/1620131033474822144
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023-01-12
tags:
    - attack.credential-access
    - attack.stealth
    - attack.t1564
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/mount'
        CommandLine|contains|all:
            - 'hidepid=2'
            - ' -o '
    condition: selection
falsepositives:
    - Unknown
level: medium
