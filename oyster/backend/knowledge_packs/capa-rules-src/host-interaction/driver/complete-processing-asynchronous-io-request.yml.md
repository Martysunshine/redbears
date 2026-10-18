<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/driver/complete-processing-asynchronous-io-request.yml -->
rule:
  meta:
    name: complete processing asynchronous IO request
    namespace: host-interaction/driver
    authors:
      - moritz.raabe@mandiant.com
    description: signals that driver has finished all processing for a given IRP (part of major function)
    scopes:
      static: basic block
      dynamic: span of calls
    examples:
      - Practical Malware Analysis Lab 10-03.sys_:0x10666
  features:
    - or:
      - api: IoCompleteRequest
      - api: IofCompleteRequest
