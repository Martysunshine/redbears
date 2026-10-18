<!-- source: https://github.com/OISF/suricata/blob/9a2b7004716b750f390ee52cf6053c97398d7af3/doc/userguide/lua/libs/index.rst -->
Lua Libraries
=============

Suricata provides Lua extensions, or libraries to Lua scripts with the
``require`` keyword. These extensions are particularly important in
Lua rules as Lua rules are executed in a restricted sandbox
environment without access to additional modules.

.. toctree::

   base64
   bytevar
   config
   dnp3
   dns
   file
   flowlib
   flowint
   flowvar
   hashlib
   http
   log
   ntp
   packetlib
   rule
   smtp
   ssh
   tls
   ja3
   util
