<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2023/TA/Cozy-Bear/image_load_apt_cozy_bear_graphical_proton_dlls.yml -->
title: DLL Names Used By SVR For GraphicalProton Backdoor
id: e64c8ef3-9f98-40c8-b71e-96110991cb4c
status: test
description: Hunts known SVR-specific DLL names.
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
author: CISA
date: 2023-12-18
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.execution
    - attack.stealth
    - attack.t1574.001
    - detection.emerging-threats
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith:
            - '\AclNumsInvertHost.dll'
            - '\AddressResourcesSpec.dll'
            - '\BlendMonitorStringBuild.dll'
            - '\ChildPaletteConnected.dll'
            - '\DeregisterSeekUsers.dll'
            - '\HandleFrequencyAll.dll'
            - '\HardSwapColor.dll'
            - '\LengthInMemoryActivate.dll'
            - '\ModeBitmapNumericAnimate.dll'
            - '\ModeFolderSignMove.dll'
            - '\ParametersNamesPopup.dll'
            - '\PerformanceCaptionApi.dll'
            - '\ScrollbarHandleGet.dll'
            - '\UnregisterAncestorAppendAuto.dll'
            - '\WowIcmpRemoveReg.dll'
    condition: selection
falsepositives:
    - Unknown
level: medium
