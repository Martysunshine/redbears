<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/file-system/meta/set-file-attributes.yml -->
rule:
  meta:
    name: set file attributes
    namespace: host-interaction/file-system/meta
    authors:
      - moritz.raabe@mandiant.com
      - michael.hunhoff@mandiant.com
      - anushka.virgaonkar@mandiant.com
    scopes:
      static: basic block
      dynamic: call
    att&ck:
      - Defense Evasion::File and Directory Permissions Modification [T1222]
    mbc:
      - File System::Set File Attributes [C0050]
    examples:
      - 946A99F36A46D335DEC080D9A4371940:0x100015f0
      - B5F85C26D7AA5A1FB4AF5821B6B5AB9B:0x4028B6
  features:
    - or:
      - api: kernel32.SetFileAttributes
      - api: ZwSetInformationFile
      - api: NtSetInformationFile
      - api: System.IO.File::SetAttributes
      - api: System.IO.File::SetCreationTime
      - api: System.IO.File::SetCreationTimeUtc
      - api: System.IO.File::SetLastAccessTime
      - api: System.IO.File::SetLastAccessTimeUtc
      - api: System.IO.File::SetLastWriteTime
      - api: System.IO.File::SetLastWriteTimeUtc
      - property/write: System.IO.FileSystemInfo::Attributes
      - api: utime
      - api: utimes
