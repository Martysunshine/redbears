<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/thread/resume/resume-thread.yml -->
rule:
  meta:
    name: resume thread
    namespace: host-interaction/thread/resume
    authors:
      - 0x534a@mailbox.org
      - anushka.virgaonkar@mandiant.com
    scopes:
      static: basic block
      dynamic: call
    mbc:
      - Process::Resume Thread [C0054]
    examples:
      - Practical Malware Analysis Lab 12-02.exe_:0x4010EA
      - 787cbc8a6d1bc58ea169e51e1ad029a637f22560660cc129ab8a099a745bd50e:0x4044C7
  features:
    - or:
      - api: kernel32.ResumeThread
      - api: ntdll.NtResumeThread
      - api: ntdll.ZwResumeThread
      - api: System.Threading.Thread::Resume
