<!-- source: https://github.com/falcosecurity/falco-website/blob/c2cf6a9ef7d1ee48cc4189cc47f5e432a01628eb/content/en/docs/reference/glossary/source-plugins.md -->
---
title: Source Plugins
id: source-plugins
date: 2023-07-17
full_link: /docs/plugins/architecture/#event-sourcing-capability
short_description: >
  A source plugin provides a new event source.
aka:
tags:
- extension
- integration
---
A source {{< glossary_tooltip text="plugin" term_id="plugins" >}} provides a new event source.

<!--more--> 
It has the ability to "open" and "close" a session that provides events. A source plugin can also be an {{< glossary_tooltip text="extractor" term_id="extractor-plugins" >}}.
