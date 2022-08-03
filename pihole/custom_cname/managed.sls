# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- set sls_package_install = tplroot ~ '.package.install' %}
{%- set sls_service_running = tplroot ~ '.service.running' %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

include:
  - {{ sls_package_install }}
  - {{ sls_service_running }}

{%- if pihole.custom_cname.present %}

PiHole custom CNAME entries are managed:
  pihole.cname:
    - names:
{%-   for cname, target in pihole.custom_cname.present.items() %}
      - {{ cname }}:
        - target: {{ target }}
{%-   endfor %}
    - require:
      - sls: {{ sls_package_install }}
    - watch_in:
      - pihole-service-running-service-running
{%- endif %}

{%- if pihole.custom_cname.absent %}

PiHole unwanted CNAME entries are absent:
  pihole.cname_absent:
    - names:
{%-   for cname in pihole.custom_cname.absent %}
{%-     if cname is mapping %}
      - {{ cname | first }}:
        - target: {{ cname[cname | first] }}
{%-     else %}
      - {{ cname }}
{%-     endif %}
{%-   endfor %}
    - require:
      - sls: {{ sls_package_install }}
    - watch_in:
      - pihole-service-running-service-running
{%- endif %}
