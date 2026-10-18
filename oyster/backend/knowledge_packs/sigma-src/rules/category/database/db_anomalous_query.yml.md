<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/category/database/db_anomalous_query.yml -->
title: Suspicious SQL Query
id: d84c0ded-edd7-4123-80ed-348bb3ccc4d5
status: test
description: Detects suspicious SQL query keywrods that are often used during recon, exfiltration or destructive activities. Such as dropping tables and selecting wildcard fields
author: '@juju4'
date: 2022-12-27
references:
    - https://github.com/sqlmapproject/sqlmap
tags:
    - attack.exfiltration
    - attack.initial-access
    - attack.privilege-escalation
    - attack.persistence
    - attack.t1190
    - attack.t1505.001
logsource:
    category: database
    definition: 'Requirements: Must be able to log the SQL queries'
detection:
    keywords:
        - 'drop'
        - 'truncate'
        - 'dump'
        - 'select \*'
    condition: keywords
falsepositives:
    - Inventory and monitoring activity
    - Vulnerability scanners
    - Legitimate applications
level: medium
