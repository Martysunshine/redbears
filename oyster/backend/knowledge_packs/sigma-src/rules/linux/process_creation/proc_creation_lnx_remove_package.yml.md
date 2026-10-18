<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_remove_package.yml -->
title: Linux Package Uninstall
id: 95d61234-7f56-465c-6f2d-b562c6fedbc4
status: test
description: Detects linux package removal using builtin tools such as "yum", "apt", "apt-get" or "dpkg".
references:
    - https://sysdig.com/blog/mitre-defense-evasion-falco
    - https://www.tutorialspoint.com/how-to-install-a-software-on-linux-using-yum-command
    - https://linuxhint.com/uninstall_yum_package/
    - https://linuxhint.com/uninstall-debian-packages/
author: Tuan Le (NCSGroup), Nasreddine Bencherchali (Nextron Systems)
date: 2023-03-09
tags:
    - attack.stealth
    - attack.t1070
logsource:
    product: linux
    category: process_creation
detection:
    selection_yum:
        Image|endswith: '/yum'
        CommandLine|contains:
            - 'erase'
            - 'remove'
    selection_apt:
        Image|endswith:
            - '/apt'
            - '/apt-get'
        CommandLine|contains:
            - 'remove'
            - 'purge'
    selection_dpkg:
        Image|endswith: '/dpkg'
        CommandLine|contains:
            - '--remove '
            - ' -r '
    selection_rpm:
        Image|endswith: '/rpm'
        CommandLine|contains: ' -e '
    condition: 1 of selection_*
falsepositives:
    - Administrator or administrator scripts might delete packages for several reasons (debugging, troubleshooting).
level: low
