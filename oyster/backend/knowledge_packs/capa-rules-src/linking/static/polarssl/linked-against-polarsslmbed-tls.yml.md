<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/linking/static/polarssl/linked-against-polarsslmbed-tls.yml -->
rule:
  meta:
    name: linked against PolarSSL/mbed TLS
    namespace: linking/static/polarssl
    authors:
      - william.ballenthin@mandiant.com
    scopes:
      static: file
      dynamic: file
    mbc:
      - Cryptography::Crypto Library [C0059]
    examples:
      - 232b0a8546035d9017fadf68398826edb0a1e055566bc1d356d6c9fdf1d7e485
  features:
    - or:
      - string: "PolarSSLTest"
      - string: "mbedtls_cipher_setup"
      - string: "mbedtls_pk_verify"
      - string: "mbedtls_ssl_write_record"
      - string: "mbedtls_ssl_fetch_input"
