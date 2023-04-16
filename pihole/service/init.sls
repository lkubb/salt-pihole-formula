# vim: ft=sls

{#-
    Starts the pihole-FTL service and enables it at boot time.
    Has a dependency on `pihole.config`_.
#}

include:
  - .running
