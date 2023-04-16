# vim: ft=sls

{#-
    Manages PiHole blacklist entries.
    Has a dependency on `pihole.service`_.
#}

include:
  - .managed
