<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/hardware/keyboard/get-keyboard-layout.yml -->
rule:
  meta:
    name: get keyboard layout
    namespace: host-interaction/hardware/keyboard
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Discovery::System Location Discovery::System Language Discovery [T1614.001]
    examples:
      - 6F99A2C8944CB02FF28C6F9CED59B161:0x4193C0
      - C91887D861D9BD4A5872249B641BC9F9:0x4015FD
  features:
    - and:
      - or:
        - api: user32.GetKeyboardLayoutList
        - api: user32.GetKeyboardLayout
        - api: user32.GetKeyboardLayoutName
      - optional:
        - api: kernel32.GetLocaleInfo
