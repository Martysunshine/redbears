<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2023/TA/Peach-Sandstorm/proc_creation_win_apt_peach_sandstorm_indicators.yml -->
title: Peach Sandstorm APT Process Activity Indicators
id: 2e7bbd54-2f26-476e-b4a1-ba5f1a012614
status: test
description: Detects process creation activity related to Peach Sandstorm APT
references:
    - https://twitter.com/MsftSecIntel/status/1737895710169628824
    - https://www.virustotal.com/gui/file/364275326bbfc4a3b89233dabdaf3230a3d149ab774678342a40644ad9f8d614/details
author: X__Junior (Nextron Systems)
date: 2024-01-15
tags:
    - attack.execution
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'QP''s\*(58vaP!tF4'
    condition: selection
falsepositives:
    - Unlikely
level: high
