# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- set sls_package_install = tplroot ~ '.package.install' %}
{%- set sls_service_running = tplroot ~ '.service.running' %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

include:
  - {{ sls_package_install }}
  - {{ sls_service_running }}

{%- for btype in ["plain", "regex", "wildcard"] %}
{%-   if pihole.blacklist.present[btype] %}

PiHole {{ btype }} blacklist entries are managed:
  pihole.blacklist:
    - domains: {{ pihole.blacklist.present[btype] | json }}
{%-     if "plain" != btype %}
    - {{ btype }}: true
{%-     endif %}
    - require:
      - sls: {{ sls_package_install }}
    - watch_in:
      - pihole-service-running-service-running
{%-   endif %}

{%-   if pihole.blacklist.absent[btype] %}

PiHole unwanted {{ btype }} blacklist entries are absent:
  pihole.blacklist_absent:
    - domains: {{ pihole.blacklist.absent[btype] | json }}
{%-     if "plain" != btype %}
    - {{ btype }}: true
{%-     endif %}
    - require:
      - sls: {{ sls_package_install }}
    - watch_in:
      - pihole-service-running-service-running
{%-   endif %}
{%- endfor %}
