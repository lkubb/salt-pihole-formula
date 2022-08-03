# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

# This does not restart PiHole on its own. To apply, you will need to restart manually.
{%- if pihole.custom_dns.present %}

PiHole wanted custom DNS A/AAAA entries are absent:
  pihole.custom_dns_absent:
    - names:
{%-   for domain, target in pihole.custom_dns.present.items() %}
      - {{ domain }}:
        - ip: {{ target }}
{%-   endfor %}
    - require:
      - sls: {{ sls_package_install }}
{%- endif %}
