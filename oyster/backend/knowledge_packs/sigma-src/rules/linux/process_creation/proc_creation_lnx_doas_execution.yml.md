<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_doas_execution.yml -->
title: Linux Doas Tool Execution
id: 067d8238-7127-451c-a9ec-fa78045b618b
status: stable
description: Detects the doas tool execution in linux host platform. This utility tool allow standard users to perform tasks as root, the same way sudo does.
references:
    - https://research.splunk.com/endpoint/linux_doas_tool_execution/
    - https://www.makeuseof.com/how-to-install-and-use-doas/
author: Sittikorn S, Teoderick Contreras
date: 2022-01-20
tags:
    - attack.privilege-escalation
    - attack.t1548
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/doas'
    condition: selection
falsepositives:
    - Unlikely
level: low
