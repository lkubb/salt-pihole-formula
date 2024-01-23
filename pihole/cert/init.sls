# vim: ft=sls

{#-
    Generates a TLS certificate + key for PiHole.
    Depends on `pihole.package`_.
#}

include:
  - .managed
