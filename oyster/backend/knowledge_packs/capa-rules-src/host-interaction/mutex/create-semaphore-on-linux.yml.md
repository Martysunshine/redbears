<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/mutex/create-semaphore-on-linux.yml -->
rule:
  meta:
    name: create semaphore on Linux
    namespace: host-interaction/mutex
    authors:
      - "@ramen0x3f"
    scopes:
      static: function
      dynamic: span of calls
    examples:
      - 294b8db1f2702b60fb2e42fdc50c2cee6a5046112da9a5703a548a4fa50477bc:0x408de0
  features:
    - and:
      - or:
        - os: linux
        - os: android
      - api: sem_init
