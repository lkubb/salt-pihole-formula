# vim: ft=sls

{#-
    Removes the PiHole, pihole-FTL and custom dnsmasq configurations and has a
    dependency on `pihole.service.clean`_.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_service_clean = tplroot ~ ".service.clean" %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

include:
  - {{ sls_service_clean }}

PiHole configuration is absent:
  file.absent:
    - names:
      - {{ pihole.lookup.config }}
      - {{ salt["file.basename"](pihole.lookup.config) | path_join("pihole-FTL.conf") }}
      - {{ pihole.lookup.config_dnsmasq }}
    - require:
      - sls: {{ sls_service_clean }}
