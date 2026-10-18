<!-- source: https://github.com/OISF/suricata/blob/9a2b7004716b750f390ee52cf6053c97398d7af3/doc/userguide/lua/libs/util.rst -->
Util
####

The ``suricata.util`` library provides utility functions for Lua
scripts.

Setup
*****

The library must be loaded prior to use::

    local util = require("suricata.util")

Functions
=========

.. function:: thread_info()

   Get information about the current thread.

   :returns: Table containing thread information with the following fields:

      - ``id`` (number): Thread ID
      - ``name`` (string): Thread name 
            
   Example::

       local util = require("suricata.util")
       
       local info = util.thread_info()
       print("Thread ID: " .. info.id)
       print("Thread Name: " .. info.name)
