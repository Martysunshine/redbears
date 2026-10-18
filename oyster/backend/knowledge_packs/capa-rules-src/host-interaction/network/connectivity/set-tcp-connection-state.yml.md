<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/network/connectivity/set-tcp-connection-state.yml -->
rule:
  meta:
    name: set TCP connection state
    namespace: host-interaction/network/connectivity
    authors:
      - "@johnk3r"
    description: The SetTcpEntry function sets the state of a TCP connection.
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Defense Evasion::Impair Defenses [T1562]
    references:
      - https://unit42.paloaltonetworks.com/evilgrab-delivered-by-watering-hole-attack-on-president-of-myanmars-website
      - https://github.com/magisterquis/EDRSniper/blob/master/edrsniper.c
    examples:
      - 883bf161937f8dc6e766b07000110254:0x403150
  features:
    - and:
      - api: iphlpapi.SetTcpEntry
      - number: 12 = MIB_TCP_STATE_DELETE_TCB
