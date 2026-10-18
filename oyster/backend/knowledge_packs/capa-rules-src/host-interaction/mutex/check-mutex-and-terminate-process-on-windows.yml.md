<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/mutex/check-mutex-and-terminate-process-on-windows.yml -->
rule:
  meta:
    name: check mutex and terminate process on Windows
    namespace: host-interaction/mutex
    authors:
      - "@_re_fox"
      - moritz.raabe@mandiant.com
      - mehunhoff@google.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Process::Check Mutex [C0043]
      - Process::Terminate Process [C0018]
    examples:
      - 1d8fd13c890060464019c0f07b928b1a:0x402eb0
  features:
    - and:
      - match: check mutex on Windows
      - match: terminate process
