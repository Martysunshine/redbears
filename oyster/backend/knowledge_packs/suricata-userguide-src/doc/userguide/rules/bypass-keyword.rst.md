<!-- source: https://github.com/OISF/suricata/blob/9a2b7004716b750f390ee52cf6053c97398d7af3/doc/userguide/rules/bypass-keyword.rst -->
Bypass Keyword
==============

.. role:: example-rule-emphasis

Suricata has a ``bypass`` keyword that can be used in signatures to exclude
traffic from further evaluation.

The ``bypass`` keyword is useful in cases where there is a large flow expected
(e.g. Netflix, Spotify, YouTube).

The ``bypass`` keyword is considered a post-match keyword.

.. note::

   ``bypass`` cannot be used in firewall mode, not even with Threat Detection
   rules, as this could lead to bypassing the firewall altogether.

bypass
------

Bypass a flow on matching http traffic.

.. container:: example-rule

  alert http any any -> any any (http.host; \
  content:"suricata.io"; :example-rule-emphasis:`bypass;` \
  sid:10001; rev:1;)
