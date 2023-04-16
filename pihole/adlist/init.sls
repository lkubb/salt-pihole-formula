# vim: ft=sls

{#-
    Manages PiHole adlists and updates the gravity database.
    Has a dependency on `pihole.service`_.
#}

include:
  - .managed
