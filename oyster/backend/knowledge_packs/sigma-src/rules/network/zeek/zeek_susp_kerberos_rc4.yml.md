<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/network/zeek/zeek_susp_kerberos_rc4.yml -->
title: Kerberos Network Traffic RC4 Ticket Encryption
id: 503fe26e-b5f2-4944-a126-eab405cc06e5
status: test
description: Detects kerberos TGS request using RC4 encryption which may be indicative of kerberoasting
references:
    - https://adsecurity.org/?p=3458
author: sigma
date: 2020-02-12
modified: 2021-11-27
tags:
    - attack.credential-access
    - attack.t1558.003
logsource:
    product: zeek
    service: kerberos
detection:
    selection:
        request_type: 'TGS'
        cipher: 'rc4-hmac'
    computer_acct:
        service|startswith: '$'
    condition: selection and not computer_acct
falsepositives:
    - Normal enterprise SPN requests activity
level: medium
