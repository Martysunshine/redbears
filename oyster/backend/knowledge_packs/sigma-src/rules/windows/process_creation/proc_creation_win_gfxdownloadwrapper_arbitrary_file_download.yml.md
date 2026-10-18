<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_gfxdownloadwrapper_arbitrary_file_download.yml -->
title: Arbitrary File Download Via GfxDownloadWrapper.EXE
id: eee00933-a761-4cd0-be70-c42fe91731e7
status: test
description: Detects execution of GfxDownloadWrapper.exe with a URL as an argument to download file.
references:
    - https://lolbas-project.github.io/lolbas/HonorableMentions/GfxDownloadWrapper/
author: Victor Sergeev, oscd.community
date: 2020-10-09
modified: 2023-10-18
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\GfxDownloadWrapper.exe'
        CommandLine|contains:
            - 'http://'
            - 'https://'
    filter_main_known_urls:
        CommandLine|contains: 'https://gameplayapi.intel.com/'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
