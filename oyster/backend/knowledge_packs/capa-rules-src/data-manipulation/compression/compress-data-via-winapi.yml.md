<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/data-manipulation/compression/compress-data-via-winapi.yml -->
rule:
  meta:
    name: compress data via WinAPI
    namespace: data-manipulation/compression
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Collection::Archive Collected Data::Archive via Library [T1560.002]
    mbc:
      - Data::Compress Data [C0024]
    examples:
      - 638dcc3d37b3a574044233c9637d7288:0x401020
  features:
    - or:
      # these APIs are not typically intended for user mode programs.
      # they're only accessible via GetProcAddress on ntoskrnl/ntdll.
      - api: RtlDecompressBuffer
      - string: "RtlDecompressBuffer"

      - api: RtlDecompressBufferEx
      - string: "RtlDecompressBufferEx"

      - api: RtlDecompressBufferEx2
      - string: "RtlDecompressBufferEx2"

      - api: RtlCompressBuffer
      - string: "RtlCompressBuffer"

      - api: RtlCompressBufferLZNT1
      - string: "RtlCompressBufferLZNT1"
