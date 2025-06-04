# vim: ft=sls

{#-
    Manages the PiHole, pihole-FTL and custom dnsmasq configurations.
    Has a dependency on `pihole.package`_.
#}

include:
  - .password
  - .file
