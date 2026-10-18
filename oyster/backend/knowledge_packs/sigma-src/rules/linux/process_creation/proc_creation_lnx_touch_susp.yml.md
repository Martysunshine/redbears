<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_touch_susp.yml -->
title: Touch Suspicious Service File
id: 31545105-3444-4584-bebf-c466353230d2
status: test
description: Detects usage of the "touch" process in service file.
references:
    - https://blogs.blackberry.com/
    - https://twitter.com/Joseliyo_Jstnk/status/1620131033474822144
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023-01-11
tags:
    - attack.stealth
    - attack.t1070.006
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/touch'
        CommandLine|contains: ' -t '
        CommandLine|endswith: '.service'
    condition: selection
falsepositives:
    - Admin changing date of files.
level: medium
