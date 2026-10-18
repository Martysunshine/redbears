<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/firewall_as/win_firewall_as_reset_config.yml -->
title: Windows Defender Firewall Has Been Reset To Its Default Configuration
id: 04b60639-39c0-412a-9fbe-e82499c881a3
status: test
description: Detects activity when Windows Defender Firewall has been reset to its default configuration
references:
    - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd364427(v=ws.10)
author: frack113
date: 2022-02-19
modified: 2023-04-21
tags:
    - attack.defense-impairment
    - attack.t1686.003
logsource:
    product: windows
    service: firewall-as
detection:
    selection:
        EventID:
            - 2032 # Windows Defender Firewall has been reset to its default configuration
            - 2060 # Windows Defender Firewall has been reset to its default configuration. (Windows 11)
    condition: selection
level: low
