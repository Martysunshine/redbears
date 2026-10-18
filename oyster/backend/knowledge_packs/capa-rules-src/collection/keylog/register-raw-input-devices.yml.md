<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/collection/keylog/register-raw-input-devices.yml -->
rule:
  meta:
    name: register raw input devices
    namespace: collection/keylog
    authors:
      - zeze-zeze
      - michael.hunhoff@mandiant.com
    scopes:
      static: basic block
      dynamic: call
    att&ck:
      - Collection::Input Capture::Keylogging [T1056.001]
    examples:
      - 52d8e95c9883cd16d7b44e3a7adc22d6.exe_:0x140001252
  features:
    - or:
      - api: user32.RegisterRawInputDevices
