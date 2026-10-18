<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/shell_core/win_shell_core_susp_packages_installed.yml -->
title: Suspicious Application Installed
id: 83c161b6-ca67-4f33-8ad0-644a0737cf07
status: test
description: Detects suspicious application installed by looking at the added shortcut to the app resolver cache
references:
    - https://nasbench.medium.com/finding-forensic-goodness-in-obscure-windows-event-logs-60e978ea45a3
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-14
tags:
    - attack.execution
logsource:
    product: windows
    service: shell-core
detection:
    selection_name:
        EventID: 28115
        Name|contains:
            # Please add more
            - 'Zenmap'
            - 'AnyDesk'
            - 'wireshark'
            - 'openvpn'
    selection_packageid:
        EventID: 28115
        AppID|contains:
            # Please add more
            - 'zenmap.exe'
            - 'prokzult ad' # AnyDesk
            - 'wireshark'
            - 'openvpn'
    condition: 1 of selection_*
falsepositives:
    - Packages or applications being legitimately used by users or administrators
level: medium
