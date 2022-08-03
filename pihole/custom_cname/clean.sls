# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

# This does not restart PiHole on its own. To apply, you will need to restart manually.
{%- if pihole.custom_cname.present %}

PiHole wanted CNAME entries are absent:
  pihole.cname_absent:
    - names:
{%-   for cname, target in pihole.custom_cname.present.items() %}
      - {{ cname }}:
        - target: {{ target }}
{%-   endfor %}
    - require:
      - sls: {{ sls_package_install }}
{%- endif %}
