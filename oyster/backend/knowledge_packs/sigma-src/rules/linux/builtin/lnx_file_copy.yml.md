<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/builtin/lnx_file_copy.yml -->
title: Remote File Copy
id: 7a14080d-a048-4de8-ae58-604ce58a795b
status: stable
description: Detects the use of tools that copy files from or to remote systems
references:
    - https://www.cisa.gov/stopransomware/ransomware-guide
author: Ömer Günal
date: 2020-06-18
tags:
    - attack.command-and-control
    - attack.lateral-movement
    - attack.t1105
logsource:
    product: linux
detection:
    tools:
        - 'scp '
        - 'rsync '
        - 'sftp '
    filter:
        - '@'
        - ':'
    condition: tools and filter
falsepositives:
    - Legitimate administration activities
level: low
