<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_esentutl_params.yml -->
title: Esentutl Gather Credentials
id: 7df1713a-1a5b-4a4b-a071-dc83b144a101
status: test
description: Conti recommendation to its affiliates to use esentutl to access NTDS dumped file. Trickbot also uses this utilities to get MSEdge info via its module pwgrab.
references:
    - https://twitter.com/vxunderground/status/1423336151860002816
    - https://thedfirreport.com/2021/08/01/bazarcall-to-conti-ransomware-via-trickbot-and-cobalt-strike/
author: sam0x90
date: 2021-08-06
modified: 2022-10-09
tags:
    - attack.credential-access
    - attack.t1003
    - attack.t1003.003
    - attack.s0404
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'esentutl'
            - ' /p'
    condition: selection
falsepositives:
    - To be determined
level: medium
