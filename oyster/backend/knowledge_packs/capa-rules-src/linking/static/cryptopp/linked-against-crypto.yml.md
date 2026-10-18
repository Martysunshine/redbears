<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/linking/static/cryptopp/linked-against-crypto.yml -->
rule:
  meta:
    name: linked against Crypto++
    namespace: linking/static/cryptopp
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: file
      dynamic: file
    mbc:
      - Cryptography::Crypto Library [C0059]
    examples:
      - 8BA66E4B618FFDC8255F1DF01F875DDE6FD0561305D9F8307BE7BB11D02AE363
      - 66602B5FAB602CB4E6F754748D249542
  features:
    - or:
      - string: "Cryptographic algorithms are disabled after a power-up self test failed."
      - string: ": this object requires an IV"
      - string: "BER decode error"
      - string: ".?AVException@CryptoPP@@"
      - string: "FileStore: error reading file"
      - string: "StreamTransformationFilter: PKCS_PADDING cannot be used with "
