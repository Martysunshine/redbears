<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/cli/accept-command-line-arguments.yml -->
rule:
  meta:
    name: accept command line arguments
    namespace: host-interaction/cli
    authors:
      - moritz.raabe@mandiant.com
      - anushka.virgaonkar@mandiant.com
    scopes:
      static: function
      dynamic: call
    att&ck:
      - Execution::Command and Scripting Interpreter [T1059]
    mbc:
      - Execution::Command and Scripting Interpreter [E1059]
    examples:
      - e5369ac309f1be6d77afeeb3edab0ed8:0x402760
  features:
    - or:
      - api: GetCommandLine
      - api: CommandLineToArgv
      - api: System.Environment::GetCommandLineArgs
