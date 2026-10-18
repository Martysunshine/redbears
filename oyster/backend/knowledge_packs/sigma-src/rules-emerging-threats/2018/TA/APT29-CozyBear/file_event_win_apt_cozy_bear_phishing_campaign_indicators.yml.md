<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2018/TA/APT29-CozyBear/file_event_win_apt_cozy_bear_phishing_campaign_indicators.yml -->
title: APT29 2018 Phishing Campaign File Indicators
id: 3a3f81ca-652c-482b-adeb-b1c804727f74
related:
    - id: 7453575c-a747-40b9-839b-125a0aae324b # ProcessCreation
      type: derived
status: stable
description: Detects indicators of APT 29 (Cozy Bear) phishing-campaign as reported by mandiant
references:
    - https://twitter.com/DrunkBinary/status/1063075530180886529
    - https://www.mandiant.com/resources/blog/not-so-cozy-an-uncomfortable-examination-of-a-suspected-apt29-phishing-campaign
author: '@41thexplorer'
date: 2018-11-20
modified: 2023-02-20
tags:
    - attack.stealth
    - attack.t1218.011
    - detection.emerging-threats
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|contains:
            - 'ds7002.lnk'
            - 'ds7002.pdf'
            - 'ds7002.zip'
    condition: selection
falsepositives:
    - Unlikely
level: critical
