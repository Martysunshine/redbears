<!-- source: https://github.com/OWASP/mastg/blob/0e88142b5d7aad8f052b4e75199a8aad9b89d5b5/techniques/generic/MASTG-TECH-0051.md -->
---
title: Tampering and Runtime Instrumentation
platform: generic
---

First, we'll look at some simple ways to modify and instrument mobile apps. _Tampering_ means making patches or runtime changes to the app to affect its behavior. For example, you may want to deactivate SSL pinning or binary protections that hinder the testing process. _Runtime Instrumentation_ encompasses adding hooks and runtime patches to observe the app's behavior. In mobile application security however, the term loosely refers to all kinds of runtime manipulation, including overriding methods to change behavior.
