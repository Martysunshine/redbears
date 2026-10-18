<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/c2/shell/execute-shell-command-received-from-socket-on-linux.yml -->
rule:
  meta:
    name: execute shell command received from socket on Linux
    namespace: communication/c2/shell
    authors:
      - joakim@intezer.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Execution::Command and Scripting Interpreter::Unix Shell [T1059.004]
    examples:
      - 7351f8a40c5450557b24622417fc478d:0x406549
  features:
    - and:
      - os: linux
      - match: receive data on socket
      - api: system
