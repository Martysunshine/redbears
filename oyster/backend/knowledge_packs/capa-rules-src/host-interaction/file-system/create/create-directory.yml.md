<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/file-system/create/create-directory.yml -->
rule:
  meta:
    name: create directory
    namespace: host-interaction/file-system/create
    authors:
      - moritz.raabe@mandiant.com
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: call
    mbc:
      - File System::Create Directory [C0046]
    examples:
      - Practical Malware Analysis Lab 17-02.dll_:0x10008f62
      - 692f7fd6d198e804d6af98eb9e390d61:0x6000003
  features:
    - or:
      - api: kernel32.CreateDirectory
      - api: kernel32.CreateDirectoryEx
      - api: kernel32.CreateDirectoryTransacted
      - api: NtCreateDirectoryObject
      - api: ZwCreateDirectoryObject
      - api: SHCreateDirectory
      - api: SHCreateDirectoryEx
      - api: mkdir
      - api: _mkdir
      - api: _wmkdir
      - api: System.IO.Directory::CreateDirectory
      - api: System.IO.DirectoryInfo::Create
      - api: System.IO.DirectoryInfo::CreateSubdirectory
