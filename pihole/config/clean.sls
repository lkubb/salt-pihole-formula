# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- set sls_service_clean = tplroot ~ '.service.clean' %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

include:
  - {{ sls_service_clean }}

pihole-config-clean-file-absent:
  file.absent:
    - names:
      - {{ pihole.lookup.config }}
      - {{ salt["file.basename"](pihole.lookup.config) | path_join("pihole-FTL.conf") }}
    - require:
      - sls: {{ sls_service_clean }}
