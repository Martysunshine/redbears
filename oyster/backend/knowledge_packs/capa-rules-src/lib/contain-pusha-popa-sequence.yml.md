<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/lib/contain-pusha-popa-sequence.yml -->
rule:
  meta:
    name: contain pusha popa sequence
    authors:
      - moritz.raabe@mandiant.com
    lib: true
    scopes:
      static: function
      dynamic: unsupported  # requires mnemonic features
    examples:
      - a5c70086b3bc4fe64f4e7a0aa452e620:0x35007200
  features:
    - and:
      - or:
        - count(mnemonic(pusha)): 2 or more
        # vivisect
        - count(mnemonic(pushad)): 2 or more
      - or:
        - count(mnemonic(popa)): 2 or more
        # vivisect
        - count(mnemonic(popad)): 2 or more
