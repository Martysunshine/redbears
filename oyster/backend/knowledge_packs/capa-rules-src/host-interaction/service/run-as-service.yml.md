<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/service/run-as-service.yml -->
rule:
  meta:
    name: run as service
    namespace: host-interaction/service
    authors:
      - moritz.raabe@mandiant.com
      - mehunhoff@google.com
    scopes:
      static: file
      dynamic: file
    mbc:
      - Anti-Behavioral Analysis::Conditional Execution::Runs as Service [B0025.007]
    examples:
      - Practical Malware Analysis Lab 03-02.dll_
  features:
    - or:
      - export: ServiceMain
      - instruction:
        - or:
          - api: RegisterServiceCtrlHandler
          - api: RegisterServiceCtrlHandlerEx
          - api: StartServiceCtrlDispatcher
          - api: System.ServiceProcess.ServiceBase::Run
      - call:
        - or:
          - api: RegisterServiceCtrlHandler
          - api: RegisterServiceCtrlHandlerEx
          - api: StartServiceCtrlDispatcher
          - api: System.ServiceProcess.ServiceBase::Run
