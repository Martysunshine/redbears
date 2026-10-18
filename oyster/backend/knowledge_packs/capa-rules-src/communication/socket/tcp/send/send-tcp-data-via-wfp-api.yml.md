<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/socket/tcp/send/send-tcp-data-via-wfp-api.yml -->
rule:
  meta:
    name: send TCP data via WFP API
    namespace: communication/socket/tcp/send
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Communication::Socket Communication::Send TCP Data [C0001.014]
    examples:
      - 493167E85E45363D09495D0841C30648:0x404560
  features:
    - and:
      - api: fwpkclnt.FwpsStreamInjectAsync0
      - number: 0x10000 = FWPS_STREAM_FLAG_SEND
