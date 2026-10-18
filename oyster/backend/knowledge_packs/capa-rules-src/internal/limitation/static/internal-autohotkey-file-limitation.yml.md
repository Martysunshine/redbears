<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/internal/limitation/static/internal-autohotkey-file-limitation.yml -->
rule:
  meta:
    name: (internal) autohotkey file limitation
    namespace: internal/limitation/static
    authors:
      - "@mr-tz"
    description: |
      This sample appears to be compiled with AutoHotkey.

      AutoHotkey is a free, open-source scripting language for Windows that allows users to easily create scripts.
      AutoHotkey was developed from AutoIT and the scripts may be similar.
      capa cannot handle AutoHotkey scripts. This means that the results will be misleading or incomplete.
      You may have to analyze the file manually, using a tool like the AutoIt decompiler MyAut2Exe.
    scopes:
      static: file
      dynamic: file
    examples:
      - 92D8EA10EA30E8B534334A1C9857A455
  features:
    - or:
      - match: compiler/autohotkey
