<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/file-system/get-windows-directory-from-kuser_shared_data.yml -->
rule:
  meta:
    name: get Windows directory from KUSER_SHARED_DATA
    namespace: host-interaction/file-system
    authors:
      - david.cannings@pwc.com
    scopes:
      static: basic block
      dynamic: unsupported
    references:
      - http://www.rohitab.com/discuss/topic/42325-the-kuser-shared-data-structure/
      - https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi_x/kuser_shared_data/index.htm
    examples:
      - 7f15b1a47bbe031334e23653879e9661f4b8cde80c307548328fdd3aed87ca46:0x01019080
  features:
    # Fixed offset of Windows directory path in KUSER_SHARED_DATA structure; same for 32- and 64-bit Windows.
    - number: 0x7ffe0030 = KUSER_SHARED_DATA.NtSystemRoot
