<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/driver/create-device-object.yml -->
rule:
  meta:
    name: create device object
    namespace: host-interaction/driver
    authors:
      - "@mr-tz"
    scopes:
      static: function
      dynamic: span of calls
    examples:
      - Practical Malware Analysis Lab 10-03.sys_:0x00010706
  features:
    - and:
      - api: IoCreateDevice
      - optional:
        - description: sets up a symbolic link between a device object name and a user-visible name for the device
        - api: IoCreateSymbolicLink
