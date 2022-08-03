# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- set sls_package_install = tplroot ~ '.package.install' %}
{%- set sls_service_running = tplroot ~ '.service.running' %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

include:
  - {{ sls_package_install }}
  - {{ sls_service_running }}

{%- if pihole.adlists.present %}

PiHole adlists are managed:
  pihole.adlist:
    - names:
{%-   for adlist in pihole.adlists.present %}
{%-     if adlist is mapping %}
      - {{ adlist | first }}:
        - enabled: {{ adlist[adlist | first] | to_bool }}
{%-     else %}
      - {{ adlist }}
{%-     endif %}
{%-   endfor %}
    - enabled: true
    - require:
      - sls: {{ sls_package_install }}
    - watch_in:
      - pihole-service-running-service-running
{%- endif %}

{%- if pihole.adlists.absent %}

PiHole unwanted adlists are absent:
  pihole.adlist_absent:
    - names: {{ pihole.adlists.absent | json }}
    - require:
      - sls: {{ sls_package_install }}
    - watch_in:
      - pihole-service-running-service-running
{%- endif %}

{%- if pihole.adlists.present or pihole.adlists.absent %}

PiHole gravity list is updated:
  module.run:
    - pihole.update_gravity: {}
    - onchanges:
{%-   if pihole.adlists.present %}
      - PiHole adlists are managed
{%-   endif %}
{%-   if pihole.adlists.absent %}
      - PiHole unwanted adlists are absent
{%-   endif %}
{%- endif %}
