<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/identity/okta/okta_application_sign_on_policy_modified_or_deleted.yml -->
title: Okta Application Sign-On Policy Modified or Deleted
id: 8f668cc4-c18e-45fe-ad00-624a981cf88a
status: test
description: Detects when an application Sign-on Policy is modified or deleted.
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
            - application.policy.sign_on.update
            - application.policy.sign_on.rule.delete
    condition: selection
falsepositives:
    - Unknown
level: medium
