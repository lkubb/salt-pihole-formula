# vim: ft=sls

{#-
    Removes generated PiHole TLS certificate + key.
    Depends on `pihole.service.clean`_.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_service_clean = tplroot ~ ".service.clean" %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

include:
  - {{ sls_service_clean }}

{%- if pihole.cert.generate %}

PiHole key/cert is absent:
  file.absent:
    - names:
      - {{ pihole.lookup.cert.privkey }}
      - {{ pihole.lookup.cert.cert }}
    - require:
      - sls: {{ sls_service_clean }}
{%- endif %}
