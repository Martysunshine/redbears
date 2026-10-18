<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/dns_query/dns_query_win_teamviewer_domain_query_by_uncommon_app.yml -->
title: TeamViewer Domain Query By Non-TeamViewer Application
id: 778ba9a8-45e4-4b80-8e3e-34a419f0b85e
status: test
description: Detects DNS queries to a TeamViewer domain only resolved by a TeamViewer client by an image that isn't named TeamViewer (sometimes used by threat actors for obfuscation)
references:
    - https://www.teamviewer.com/en-us/
author: Florian Roth (Nextron Systems)
date: 2022-01-30
modified: 2023-09-18
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        QueryName:
            - 'taf.teamviewer.com'
            - 'udp.ping.teamviewer.com'
    filter_main_teamviewer:
        # Note: To avoid evasion based on similar names. Best add full install location of TeamViewer
        Image|contains: 'TeamViewer'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown binary names of TeamViewer
    - Depending on the environment the rule might require some initial tuning before usage to avoid FP with third party applications
level: medium
