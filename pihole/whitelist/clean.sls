# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

# This does not restart PiHole on its own. To apply, you will need to restart manually.
{%- for wtype in ["plain", "regex", "wildcard"] %}
{%-   if pihole.whitelist.present[wtype] %}

PiHole wanted {{ wtype }} whitelist entries are absent:
  pihole.whitelist_absent:
    - domains: {{ pihole.whitelist.present[wtype] | json }}
{%-     if "plain" != wtype %}
    - {{ wtype }}: true
{%-     endif %}
{%-   endif %}
{%- endfor %}
