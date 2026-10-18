<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-threat-hunting/windows/pipe_created/pipe_created_sysinternals_psexec_default_pipe.yml -->
title: PsExec Default Named Pipe
id: f3f3a972-f982-40ad-b63c-bca6afdfad7c
related:
    - id: 42c575ea-e41e-41f1-b248-8093c3e82a28
      type: derived
status: test
description: Detects PsExec service default pipe creation
references:
    - https://www.jpcert.or.jp/english/pub/sr/ir_research.html
    - https://jpcertcc.github.io/ToolAnalysisResultSheet
author: Thomas Patzke
date: 2017-06-12
modified: 2022-10-09
tags:
    - attack.execution
    - attack.t1569.002
    - attack.s0029
    - detection.threat-hunting
logsource:
    category: pipe_created
    product: windows
    definition: 'Note that you have to configure logging for Named Pipe Events in Sysmon config (Event ID 17 and Event ID 18). The basic configuration is in popular sysmon configuration (https://github.com/SwiftOnSecurity/sysmon-config), but it is worth verifying. You can also use other repo, e.g. https://github.com/Neo23x0/sysmon-config, https://github.com/olafhartong/sysmon-modular. How to test detection? You can check powershell script from this site https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575'
detection:
    selection:
        PipeName: '\PSEXESVC'
    condition: selection
falsepositives:
    - Unknown
level: low
