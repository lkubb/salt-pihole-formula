# vim: ft=sls

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_config_file = tplroot ~ ".config.file" %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

include:
  - {{ sls_config_file }}

PiHole is running:
  service.running:
    - name: {{ pihole.lookup.service.name }}
    - enable: true
    - watch:
      - sls: {{ sls_config_file }}
