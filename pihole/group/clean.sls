# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

# This does not restart PiHole on its own. To apply, you will need to restart manually.
{%- if pihole.groups.present %}

PiHole groups are managed:
  pihole.group_absent:
    - names:
{%-   for group in pihole.groups.present %}
{%-     if group is mapping %}
      - {{ group | first }}
{%-     else %}
      - {{ group }}
{%-     endif %}
{%-   endfor %}
    - require:
      - sls: {{ sls_package_install }}
{%- endif %}
