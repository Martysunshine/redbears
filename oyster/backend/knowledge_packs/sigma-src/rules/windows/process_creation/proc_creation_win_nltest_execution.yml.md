<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_nltest_execution.yml -->
title: Nltest.EXE Execution
id: 903076ff-f442-475a-b667-4f246bcc203b
related:
    - id: 5cc90652-4cbd-4241-aa3b-4b462fa5a248
      type: similar
    - id: eeb66bbb-3dde-4582-815a-584aee9fe6d1
      type: obsolete
status: test
description: Detects nltest commands that can be used for information discovery
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/nltest.htm
author: Arun Chauhan
date: 2023-02-03
tags:
    - attack.discovery
    - attack.t1016
    - attack.t1018
    - attack.t1482
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\nltest.exe'
        - OriginalFileName: 'nltestrk.exe'
    condition: selection
falsepositives:
    - Legitimate administration activity
level: low
