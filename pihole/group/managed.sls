# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- set sls_package_install = tplroot ~ '.package.install' %}
{%- set sls_service_running = tplroot ~ '.service.running' %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

include:
  - {{ sls_package_install }}
  - {{ sls_service_running }}

{%- if pihole.groups.present %}

PiHole groups are managed:
  pihole.group:
    - names:
{%-   for group in pihole.groups.present %}
{%-     if group is mapping %}
      - {{ group | first }}:
        - enabled: {{ group[group | first] | to_bool }}
{%-     else %}
      - {{ group }}
{%-     endif %}
{%-   endfor %}
    - enabled: true
    - require:
      - sls: {{ sls_package_install }}
    - watch_in:
      - pihole-service-running-service-running
{%- endif %}

{%- if pihole.groups.absent %}

PiHole unwanted groups are absent:
  pihole.group_absent:
    - names: {{ pihole.groups.absent | json }}
    - require:
      - sls: {{ sls_package_install }}
    - watch_in:
      - pihole-service-running-service-running
{%- endif %}
