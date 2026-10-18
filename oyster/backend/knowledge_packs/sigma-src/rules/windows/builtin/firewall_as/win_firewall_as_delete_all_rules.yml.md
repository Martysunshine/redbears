<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/firewall_as/win_firewall_as_delete_all_rules.yml -->
title: All Rules Have Been Deleted From The Windows Firewall Configuration
id: 79609c82-a488-426e-abcf-9f341a39365d
status: test
description: Detects when a all the rules have been deleted from the Windows Defender Firewall configuration
references:
    - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd364427(v=ws.10)
author: frack113, Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-17
modified: 2024-01-22
tags:
    - attack.defense-impairment
    - attack.t1686.003
logsource:
    product: windows
    service: firewall-as
detection:
    selection:
        EventID:
            - 2033 # All rules have been deleted from the Windows Defender Firewall configuration on this computer
            - 2059 # All rules have been deleted from the Windows Defender Firewall configuration on this computer. (Windows 11)
    filter_main_svchost:
        ModifyingApplication|endswith: ':\Windows\System32\svchost.exe'
    filter_optional_msmpeng:
        ModifyingApplication|contains|all:
            - ':\ProgramData\Microsoft\Windows Defender\Platform\'
            - '\MsMpEng.exe'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
level: high
