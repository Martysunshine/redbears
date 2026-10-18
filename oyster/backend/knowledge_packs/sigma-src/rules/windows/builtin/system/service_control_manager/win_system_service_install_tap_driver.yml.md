<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/system/service_control_manager/win_system_service_install_tap_driver.yml -->
title: Tap Driver Installation
id: 8e4cf0e5-aa5d-4dc3-beff-dc26917744a9
status: test
description: Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques
references:
    - https://community.openvpn.net/openvpn/wiki/ManagingWindowsTAPDrivers
author: Daniil Yugoslavskiy, Ian Davis, oscd.community
date: 2019-10-24
modified: 2022-12-25
tags:
    - attack.exfiltration
    - attack.t1048
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ImagePath|contains: 'tap0901'
    condition: selection
falsepositives:
    - Legitimate OpenVPN TAP installation
level: medium
