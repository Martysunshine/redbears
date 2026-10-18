<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/identity/okta/okta_user_created.yml -->
title: New Okta User Created
id: b6c718dd-8f53-4b9f-98d8-93fdca966969
status: test
description: Detects new user account creation
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-10-25
modified: 2026-04-27
references:
    - https://developer.okta.com/docs/reference/api/event-types/
tags:
    - attack.credential-access
logsource:
    service: okta
    product: okta
detection:
    selection:
        eventType: 'user.lifecycle.create'
    condition: selection
falsepositives:
    - Legitimate and authorized user creation
level: informational
