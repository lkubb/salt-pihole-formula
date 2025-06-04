# vim: ft=sls

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_config_file = tplroot ~ ".config.file" %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

include:
  - {{ sls_config_file }}

# After migration from 5->6, ensure lighttpd not running
Lighttpd is disabled:
  service.dead:
    - name: lighttpd
    - enable: false

PiHole is running:
  service.running:
    - name: {{ pihole.lookup.service.name }}
    - enable: true
    - require:
      - service: lighttpd
    - watch:
      - sls: {{ sls_config_file }}
