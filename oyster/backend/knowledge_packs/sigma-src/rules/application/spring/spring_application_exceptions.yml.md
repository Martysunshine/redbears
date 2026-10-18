<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/spring/spring_application_exceptions.yml -->
title: Spring Framework Exceptions
id: ae48ab93-45f7-4051-9dfe-5d30a3f78e33
status: stable
description: Detects suspicious Spring framework exceptions that could indicate exploitation attempts
references:
    - https://docs.spring.io/spring-security/site/docs/current/api/overview-tree.html
author: Thomas Patzke
date: 2017-08-06
modified: 2020-09-01
tags:
    - attack.initial-access
    - attack.t1190
logsource:
    category: application
    product: spring
detection:
    keywords:
        - AccessDeniedException
        - CsrfException
        - InvalidCsrfTokenException
        - MissingCsrfTokenException
        - CookieTheftException
        - InvalidCookieException
        - RequestRejectedException
    condition: keywords
falsepositives:
    - Application bugs
level: medium
