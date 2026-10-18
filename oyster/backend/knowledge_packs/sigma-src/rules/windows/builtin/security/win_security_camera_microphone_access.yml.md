<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/security/win_security_camera_microphone_access.yml -->
title: Processes Accessing the Microphone and Webcam
id: 8cd538a4-62d5-4e83-810b-12d41e428d6e
status: test
description: Potential adversaries accessing the microphone and webcam in an endpoint.
references:
    - https://twitter.com/duzvik/status/1269671601852813320
    - https://medium.com/@7a616368/can-you-track-processes-accessing-the-camera-and-microphone-7e6885b37072
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2020-06-07
modified: 2021-11-27
tags:
    - attack.collection
    - attack.t1123
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4657
            - 4656
            - 4663
        ObjectName|contains:
            - '\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged'
            - '\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged'
    condition: selection
falsepositives:
    - Unknown
level: medium
