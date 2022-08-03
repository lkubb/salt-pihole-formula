# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

# This does not restart PiHole on its own. To apply, you will need to restart manually.
{%- if pihole.adlists.present %}

PiHole wanted adlists are absent:
  pihole.adlist_absent:
    - names:
{%-   for adlist in pihole.adlists.present %}
{%-     if adlist is mapping %}
      - {{ adlist | first }}
{%-     else %}
      - {{ adlist }}
{%-     endif %}
{%-   endfor %}

PiHole gravity list is updated:
  module.run:
    - pihole.update_gravity: {}
    - onchanges:
      - PiHole wanted adlists are absent
{%- endif %}
