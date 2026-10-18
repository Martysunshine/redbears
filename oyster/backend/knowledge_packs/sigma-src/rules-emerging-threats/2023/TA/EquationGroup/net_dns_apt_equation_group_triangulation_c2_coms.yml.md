<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2023/TA/EquationGroup/net_dns_apt_equation_group_triangulation_c2_coms.yml -->
title: Potential Operation Triangulation C2 Beaconing Activity - DNS
id: 7fc30d63-728d-48d9-ad6f-14d14f4accf7
related:
    - id: aa03c712-75c6-438b-8d42-de88f2427e09 # Proxy C2
      type: similar
status: test
description: Detects potential beaconing activity to domains used in 0day attacks on iOS devices and revealed by Kaspersky and the FSB
references:
    - https://securelist.com/operation-triangulation/109842/
    - https://www-fsb-ru.translate.goog/fsb/press/message/single.htm!id=10439739@fsbMessage.html?_x_tr_sch=http&_x_tr_sl=ru&_x_tr_tl=en&_x_tr_hl=de&_x_tr_pto=wapp
author: Florian Roth (Nextron Systems)
date: 2023-06-01
tags:
    - attack.command-and-control
    - attack.g0020
    - detection.emerging-threats
logsource:
    category: dns
detection:
    selection:
        query:
            - 'addatamarket.net'
            - 'ans7tv.net'
            - 'anstv.net'
            - 'backuprabbit.com'
            - 'businessvideonews.com'
            - 'cloudsponcer.com'
            - 'datamarketplace.net'
            - 'growthtransport.com'
            - 'mobilegamerstats.com'
            - 'snoweeanalytics.com'
            - 'tagclick-cdn.com'
            - 'topographyupdates.com'
            - 'unlimitedteacup.com'
            - 'virtuallaughing.com'
            - 'web-trackers.com'
    condition: selection
falsepositives:
    - Unknown
level: high
