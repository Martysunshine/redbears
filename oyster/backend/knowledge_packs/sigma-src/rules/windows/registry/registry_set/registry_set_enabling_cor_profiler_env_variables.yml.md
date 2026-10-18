<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/registry/registry_set/registry_set_enabling_cor_profiler_env_variables.yml -->
title: Enabling COR Profiler Environment Variables
id: ad89044a-8f49-4673-9a55-cbd88a1b374f
status: test
description: Detects .NET Framework CLR and .NET Core CLR "cor_enable_profiling" and "cor_profiler" variables being set and configured.
references:
    - https://twitter.com/jamieantisocial/status/1304520651248668673
    - https://www.slideshare.net/JamieWilliams130/started-from-the-bottom-exploiting-data-sources-to-uncover-attck-behaviors
    - https://www.sans.org/cyber-security-summit/archives
    - https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling
author: Jose Rodriguez (@Cyb3rPandaH), OTR (Open Threat Research), Jimmy Bayne (@bohops)
date: 2020-09-10
modified: 2023-11-24
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.execution
    - attack.stealth
    - attack.t1574.012
logsource:
    category: registry_set
    product: windows
detection:
    selection_1:
        TargetObject|endswith:
            - '\COR_ENABLE_PROFILING'
            - '\COR_PROFILER'
            - '\CORECLR_ENABLE_PROFILING'
    selection_2:
        TargetObject|contains: '\CORECLR_PROFILER_PATH'
    condition: 1 of selection_*
level: medium
