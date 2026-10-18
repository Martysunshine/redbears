<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/file-system/delete/delete-directory.yml -->
rule:
  meta:
    name: delete directory
    namespace: host-interaction/file-system/delete
    authors:
      - moritz.raabe@mandiant.com
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: call
    mbc:
      - File System::Delete Directory [C0048]
    examples:
      - Practical Malware Analysis Lab 05-01.dll_:0x10009236
      - AFB6EC3D721A5CB67863487B0E51A34C167F629CF701F8BC7A038C117B4DDA44:0x429AA0
  features:
    - or:
      - api: RemoveDirectory
      - api: RemoveDirectoryTransacted
      - api: rmdir
      - api: _rmdir
      - api: _wrmdir
      - api: System.IO.DirectoryInfo::Delete
      - api: System.IO.Directory::Delete
