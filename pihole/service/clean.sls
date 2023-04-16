# vim: ft=sls

{#-
    Stops the pihole-FTL service and disables it at boot time.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

PiHole is dead:
  service.dead:
    - name: {{ pihole.lookup.service.name }}
    - enable: false
