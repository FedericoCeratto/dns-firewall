
.. image:: https://pypip.in/download/dns-firewall/badge.png
    :target: https://pypi.python.org/pypi/dns-firewall/
    :alt: Downloads

.. image:: https://pypip.in/version/dns-firewall/badge.png
    :target: https://pypi.python.org/pypi/dns-firewall/
    :alt: Latest Version

.. image:: https://pypip.in/license/dns-firewall/badge.png
    :target: https://pypi.python.org/pypi/dns-firewall/
    :alt: License

DNS firewall
============

A proxy to inspect and mingle locally generated DNS queries.
Optional tray icon an Gtk interface.

Features
--------

* Block DNS queries by application and domain, or return configurable IP addresses
* Tray icon with activity indicators
* Log window to inspect recent activity

Usage
-----

Binding to UDP port 53 is required. You can run the process as root or install
and configure authbind::

   sudo apt-get install authbind
   sudo touch /etc/authbind/byport/53
   authbind --depth 2 ./dns_firewall/main.py conf.yaml

   # or

   sudo ./dns_firewall/main.py conf.yaml

Add --tray to enable the tray icon and Gtk interface.

Create conf.yaml from conf.yaml.example

Update your /etc/resolv.conf with "nameserver 127.0.0.1"

Development status
------------------

In development. Testing and contributions are welcome!
