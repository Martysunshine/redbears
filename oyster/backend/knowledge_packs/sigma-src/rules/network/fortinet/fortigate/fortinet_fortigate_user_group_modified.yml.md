<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/network/fortinet/fortigate/fortinet_fortigate_user_group_modified.yml -->
title: FortiGate - User Group Modified
id: 69ffc84e-8b1a-4024-8351-e018f66b8275
status: experimental
description: |
    Detects the modification of a user group on a Fortinet FortiGate Firewall.
    The group could be used to grant VPN access to a network.
references:
    - https://www.fortiguard.com/psirt/FG-IR-24-535
    - https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/398/event
    - https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/328136827/config-user-group
    - https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/44547/44547-logid-event-config-objattr
author: Marco Pedrinazzi (@pedrinazziM) (InTheCyber)
date: 2025-11-01
tags:
    - attack.persistence
    - attack.privilege-escalation
    # - attack.t1098.007
logsource:
    product: fortigate
    service: event
detection:
    selection:
        action: 'Edit'
        cfgpath: 'user.group'
    condition: selection
falsepositives:
    - A group can be modified for legitimate purposes.
level: medium
