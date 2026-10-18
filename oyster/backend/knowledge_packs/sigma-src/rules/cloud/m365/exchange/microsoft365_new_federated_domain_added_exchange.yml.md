<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/m365/exchange/microsoft365_new_federated_domain_added_exchange.yml -->
title: New Federated Domain Added - Exchange
id: 42127bdd-9133-474f-a6f1-97b6c08a4339
related:
    - id: 58f88172-a73d-442b-94c9-95eaed3cbb36
      type: similar
status: test
description: Detects the addition of a new Federated Domain.
references:
    - https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf
    - https://us-cert.cisa.gov/ncas/alerts/aa21-008a
    - https://www.splunk.com/en_us/blog/security/a-golden-saml-journey-solarwinds-continued.html
    - https://www.sygnia.co/golden-saml-advisory
    - https://o365blog.com/post/aadbackdoor/
author: Splunk Threat Research Team (original rule), '@ionsor (rule)'
date: 2022-02-08
tags:
    - attack.persistence
    - attack.t1136.003
logsource:
    service: exchange
    product: m365
detection:
    selection:
        eventSource: Exchange
        eventName: 'Add-FederatedDomain'
        status: success
    condition: selection
falsepositives:
    - The creation of a new Federated domain is not necessarily malicious, however these events need to be followed closely, as it may indicate federated credential abuse or backdoor via federated identities at a similar or different cloud provider.
level: medium
