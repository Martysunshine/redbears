<!-- source: https://github.com/OISF/suricata/blob/9a2b7004716b750f390ee52cf6053c97398d7af3/doc/userguide/initscripts.rst -->
Init Scripts
============

For Ubuntu with Upstart, the following can be used in ``/etc/init/suricata.conf``:


::


  # suricata
  description "Intrusion Detection System Daemon"
  start on runlevel [2345]
  stop on runlevel [!2345]
  expect fork
  exec suricata -D --pidfile /var/run/suricata.pid -c /etc/suricata/suricata.yaml -i eth1
