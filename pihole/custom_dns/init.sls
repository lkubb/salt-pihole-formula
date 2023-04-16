# vim: ft=sls

{#-
    Manages PiHole local DNS A/AAAA entries.
    Has a dependency on `pihole.service`_.
#}

include:
  - .managed
