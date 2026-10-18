<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/macos/process_creation/proc_creation_macos_installer_susp_child_process.yml -->
title: Suspicious Installer Package Child Process
id: e0cfaecd-602d-41af-988d-f6ccebb2af26
status: test
description: Detects the execution of suspicious child processes from macOS installer package parent process. This includes osascript, JXA, curl and wget amongst other interpreters
references:
    - https://redcanary.com/blog/clipping-silver-sparrows-wings/
    - https://github.com/elastic/detection-rules/blob/4312d8c9583be524578a14fe6295c3370b9a9307/rules/macos/execution_installer_package_spawned_network_event.toml
author: Sohan G (D4rkCiph3r)
date: 2023-02-18
tags:
    - attack.t1059
    - attack.t1059.007
    - attack.t1071
    - attack.t1071.001
    - attack.execution
    - attack.command-and-control
logsource:
    category: process_creation
    product: macos
detection:
    selection_installer:
        ParentImage|endswith:
            - '/package_script_service'
            - '/installer'
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/dash'
            - '/python'
            - '/ruby'
            - '/perl'
            - '/php'
            - '/javascript'
            - '/osascript'
            - '/tclsh'
            - '/curl'
            - '/wget'
        CommandLine|contains:
            - 'preinstall'
            - 'postinstall'
    condition: selection_installer
falsepositives:
    - Legitimate software uses the scripts (preinstall, postinstall)
level: medium
