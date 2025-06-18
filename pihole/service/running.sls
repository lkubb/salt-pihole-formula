# vim: ft=sls

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_config_file = tplroot ~ ".config.file" %}
{%- set sls_cert_managed = tplroot ~ ".cert.managed" %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

include:
  - {{ sls_config_file }}
  - {{ sls_cert_managed }}

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
      - sls: {{ sls_cert_managed }}
