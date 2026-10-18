<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/python/app_python_sql_exceptions.yml -->
title: Python SQL Exceptions
id: 19aefed0-ffd4-47dc-a7fc-f8b1425e84f9
status: stable
description: Generic rule for SQL exceptions in Python according to PEP 249
references:
    - https://www.python.org/dev/peps/pep-0249/#exceptions
author: Thomas Patzke
date: 2017-08-12
modified: 2020-09-01
tags:
    - attack.initial-access
    - attack.t1190
logsource:
    category: application
    product: python
detection:
    keywords:
        - DataError
        - IntegrityError
        - ProgrammingError
        - OperationalError
    condition: keywords
falsepositives:
    - Application bugs
level: medium
