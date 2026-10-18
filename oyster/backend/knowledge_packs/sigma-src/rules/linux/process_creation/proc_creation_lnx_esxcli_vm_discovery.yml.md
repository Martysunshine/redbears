<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_esxcli_vm_discovery.yml -->
title: ESXi VM List Discovery Via ESXCLI
id: 5f1573a7-363b-4114-9208-ad7a61de46eb
status: test
description: Detects execution of the "esxcli" command with the "vm" flag in order to retrieve information about the installed VMs.
references:
    - https://www.crowdstrike.com/blog/hypervisor-jackpotting-ecrime-actors-increase-targeting-of-esxi-servers/
    - https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_vm.html
    - https://www.secuinfra.com/en/techtalk/hide-your-hypervisor-analysis-of-esxiargs-ransomware/
    - https://www.trendmicro.com/en_us/research/22/e/new-linux-based-ransomware-cheerscrypt-targets-exsi-devices.html
author: Cedric Maurugeon
date: 2023-09-04
tags:
    - attack.discovery
    - attack.execution
    - attack.t1033
    - attack.t1007
    - attack.t1059.012
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/esxcli'
        CommandLine|contains: 'vm process'
        CommandLine|endswith: ' list'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium
