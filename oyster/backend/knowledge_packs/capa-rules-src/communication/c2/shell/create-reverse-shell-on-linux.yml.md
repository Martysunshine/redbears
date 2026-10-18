<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/c2/shell/create-reverse-shell-on-linux.yml -->
rule:
  meta:
    name: create reverse shell on Linux
    namespace: communication/c2/shell
    authors:
      - joakim@intezer.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Execution::Command and Scripting Interpreter::Unix Shell [T1059.004]
    mbc:
      - Impact::Remote Access::Reverse Shell [B0022.001]
    examples:
      - 7351f8a40c5450557b24622417fc478d:0x40231E
  features:
    - and:
      - os: linux
      - match: duplicate stdin and stdout
      - match: host-interaction/process/create
