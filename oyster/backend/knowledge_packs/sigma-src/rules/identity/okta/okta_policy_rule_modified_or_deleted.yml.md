<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/identity/okta/okta_policy_rule_modified_or_deleted.yml -->
title: Okta Policy Rule Modified or Deleted
id: 0c97c1d3-4057-45c9-b148-1de94b631931
status: test
description: Detects when an Policy Rule is Modified or Deleted.
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
            - policy.rule.update
            - policy.rule.delete
    condition: selection
falsepositives:
    - Unknown

level: medium
