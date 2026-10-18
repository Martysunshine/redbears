<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/identity/okta/okta_application_modified_or_deleted.yml -->
title: Okta Application Modified or Deleted
id: 7899144b-e416-4c28-b0b5-ab8f9e0a541d
status: test
description: Detects when an application is modified or deleted.
references:
    - https://developer.okta.com/docs/reference/api/system-log/
    - https://developer.okta.com/docs/reference/api/event-types/
author: Austin Songer @austinsonger
date: 2021-09-12
modified: 2026-04-27
tags:
    - attack.impact
logsource:
    product: okta
    service: okta
detection:
    selection:
        eventType:
            - application.lifecycle.update
            - application.lifecycle.delete
    condition: selection
falsepositives:
    - Unknown

level: medium
