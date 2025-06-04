# vim: ft=sls

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_package_install = tplroot ~ ".package.install" %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}
{%- from tplroot ~ "/libtofsstack.jinja" import files_switch with context %}

include:
  - {{ sls_package_install }}


PiHole API password is managed:
  pihole.api_password_managed:
    - pillar: {{ pihole.secrets.api_password.pillar | json }}
    - password: {{ pihole.secrets.api_password.plaintext | json }}
    - require:
      - sls: {{ sls_package_install }}
