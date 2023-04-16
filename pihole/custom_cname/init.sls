# vim: ft=sls

{#-
    Manages PiHole custom CNAME entries.
    Has a dependency on `pihole.service`_.
#}

include:
  - .managed
