<!-- source: https://github.com/falcosecurity/falco-website/blob/c2cf6a9ef7d1ee48cc4189cc47f5e432a01628eb/content/en/docs/reference/glossary/ring-buffer.md -->
---
title: Ring Buffer
id: ring-buffer
date: 2023-07-17
full_link: https://www.kernel.org/doc/html/next/bpf/ringbuf.html
short_description: >
  The ring buffer is a memory buffer that behaves as if it had a circular shape, used for FIFO (first in, first out).
aka:
tags:
- architecture
---
The ring buffer is a memory buffer that behaves as if it had a circular shape, used for FIFO (first in, first out).

<!--more--> 
It uses to pass the events from the driver (kernel space) to the library libscap (user space)
