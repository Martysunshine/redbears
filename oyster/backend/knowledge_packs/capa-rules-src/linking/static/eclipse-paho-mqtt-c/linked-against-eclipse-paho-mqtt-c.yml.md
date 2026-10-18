<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/linking/static/eclipse-paho-mqtt-c/linked-against-eclipse-paho-mqtt-c.yml -->
rule:
  meta:
    name: linked against Eclipse Paho MQTT C
    namespace: linking/static/eclipse-paho-mqtt-c
    authors:
      - jakubjozwiak@google.com
    scopes:
      static: file
      dynamic: file
    references:
      - https://github.com/eclipse-paho/paho.mqtt.c
    examples:
      - 80f166e9c0427f055c88c9ee62016a6ba6a938023ff8778f5a0b5f8d7fe7570d
  features:
    - or:
      - string: "mqttasync_mutex error %d"
      - string: "mqttclient_mutex error %d"
      - string: "mqttcommand_mutex error %d"
      - string: "subscribe_mutex error %d"
      - string: "MQTT version is 0 in MQTTAsync_connecting"
      - string: "Bad MQTT packet, type %d"
      - string: "memory allocation error in MQTTStrdup"
      - string: "Error from MQTTProperties add %d"
