<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/azure/audit_logs/azure_app_credential_added.yml -->
title: Added Credentials to Existing Application
id: cbb67ecc-fb70-4467-9350-c910bdf7c628
status: test
description: Detects when a new credential is added to an existing application. Any additional credentials added outside of expected processes could be a malicious actor using those credentials.
references:
    - https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications#application-credentials
author: Mark Morowczynski '@markmorow', Bailey Bercik '@baileybercik'
date: 2022-05-26
modified: 2025-07-18
tags:
    - attack.privilege-escalation
    - attack.t1098.001
    - attack.persistence
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message:
            - Update application – Certificates and secrets management
            - Update Service principal/Update Application
    condition: selection
falsepositives:
    - When credentials are added/removed as part of the normal working hours/workflows
level: high
