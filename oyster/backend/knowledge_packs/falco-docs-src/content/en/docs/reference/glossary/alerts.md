<!-- source: https://github.com/falcosecurity/falco-website/blob/c2cf6a9ef7d1ee48cc4189cc47f5e432a01628eb/content/en/docs/reference/glossary/alerts.md -->
---
title: Alerts
id: alerts
date: 2023-07-17
full_link: /docs/outputs/
short_description: >
  Downstream actions executed after a rule is triggered.
aka:
tags:
- fundamental
---
Downstream actions executed after a rule is triggered.

<!--more--> 

They can be as simple as logging to `stdout` or as complex as delivering an HTTP request to an endpoint.

Falco supports sending alerts to:

- Standard Output
- A file
- Syslog
- A spawned program
- An HTTP[s] endpoint
