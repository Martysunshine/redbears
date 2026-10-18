<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2023/TA/Mint-Sandstorm/proc_creation_win_apt_mint_sandstorm_log4j_wstomcat_execution.yml -->
title: Mint Sandstorm - Log4J Wstomcat Process Execution
id: 7c97c625-0350-4f0a-8943-f6cadc88125e
status: test
description: Detects Log4J Wstomcat process execution as seen in Mint Sandstorm activity
references:
    - https://www.microsoft.com/en-us/security/blog/2023/04/18/nation-state-threat-actor-mint-sandstorm-refines-tradecraft-to-attack-high-value-targets/
author: Nasreddine Bencherchali (Nextron Systems), MSTIC (idea)
date: 2023-04-20
modified: 2023-11-29
tags:
    - attack.execution
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\ws_tomcatservice.exe'
    filter_main_repadmin:
        Image|endswith: '\repadmin.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
