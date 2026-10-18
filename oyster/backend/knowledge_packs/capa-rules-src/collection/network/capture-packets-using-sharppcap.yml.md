<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/collection/network/capture-packets-using-sharppcap.yml -->
rule:
  meta:
    name: capture packets using SharpPcap
    namespace: collection/network
    authors:
      - jakub.jozwiak@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Discovery::Network Sniffing [T1040]
    references:
      - https://github.com/dotpcap/sharppcap
    examples:
      - aefae71bca4bbaa2c013ddf040d797628c8d3da7346108c12735239a86fdfa71:0x6000038
  features:
    - and:
      - format: dotnet
      - api: SharpPcap.LibPcap.PcapDevice::add_OnPacketArrival
