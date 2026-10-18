<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/cloud/aws/cloudtrail/aws_delete_identity.yml -->
title: SES Identity Has Been Deleted
id: 20f754db-d025-4a8f-9d74-e0037e999a9a
status: test
description: Detects an instance of an SES identity being deleted via the "DeleteIdentity" event. This may be an indicator of an adversary removing the account that carried out suspicious or malicious activities
references:
    - https://unit42.paloaltonetworks.com/compromised-cloud-compute-credentials/
author: Janantha Marasinghe
date: 2022-12-13
modified: 2022-12-28
tags:
    - attack.stealth
    - attack.t1070
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: 'ses.amazonaws.com'
        eventName: 'DeleteIdentity'
    condition: selection
falsepositives:
    - Unknown
level: medium
