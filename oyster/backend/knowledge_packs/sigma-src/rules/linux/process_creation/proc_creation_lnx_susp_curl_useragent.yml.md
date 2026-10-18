<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_susp_curl_useragent.yml -->
title: Suspicious Curl Change User Agents - Linux
id: b86d356d-6093-443d-971c-9b07db583c68
related:
    - id: 3286d37a-00fd-41c2-a624-a672dcd34e60
      type: derived
status: test
description: Detects a suspicious curl process start on linux with set useragent options
references:
    - https://curl.se/docs/manpage.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-15
tags:
    - attack.command-and-control
    - attack.t1071.001
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/curl'
        CommandLine|contains:
            - ' -A '
            - ' --user-agent '
    condition: selection
falsepositives:
    - Scripts created by developers and admins
    - Administrative activity
level: medium
