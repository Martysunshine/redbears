<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/github/audit/github_pages_site_changed_to_public.yml -->
title: GitHub Repository Pages Site Changed to Public
id: 0c46d4f4-a2bf-4104-9597-8d653fc2bb55
status: experimental
description: |
    Detects when a GitHub Pages site of a repository is made public. This usually is part of a publishing process but could indicate or lead to potential unauthorized exposure of sensitive information or code.
references:
    - https://docs.github.com/en/pages/getting-started-with-github-pages/creating-a-github-pages-site
    - https://www.sentinelone.com/blog/exploiting-repos-6-ways-threat-actors-abuse-github-other-devops-platforms
    - https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/security-log-events
author: Ivan Saakov
date: 2025-10-18
tags:
    - attack.collection
    - attack.exfiltration
    - attack.t1567.001
logsource:
    product: github
    service: audit
detection:
    selection:
        action: 'repo.pages_public'
    condition: selection
falsepositives:
    - Legitimate publishing of repository pages by authorized users
level: low
