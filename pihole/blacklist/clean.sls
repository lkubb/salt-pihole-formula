# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

# This does not restart PiHole on its own. To apply, you will need to restart manually.
{%- for btype in ["plain", "regex", "wildcard"] %}
{%-   if pihole.blacklist.present[btype] %}

PiHole wanted {{ btype }} blacklist entries are absent:
  pihole.blacklist_absent:
    - domains: {{ pihole.blacklist.present[btype] | json }}
{%-     if "plain" != btype %}
    - {{ btype }}: true
{%-     endif %}
{%-   endif %}
{%- endfor %}
