<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/log/debug/write-event/print-debug-messages.yml -->
rule:
  meta:
    name: print debug messages
    namespace: host-interaction/log/debug/write-event
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: call
    examples:
      - 493167E85E45363D09495D0841C30648:0x401000
  features:
    - or:
      - api: DbgPrint
      - api: kernel32.OutputDebugString
      - and:
        - os: android
        - api: __android_log_print
