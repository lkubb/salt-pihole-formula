# vim: ft=sls

{#-
    Removes managed PiHole blacklist entries.
    This does not restart PiHole on its own. To apply, you will need to restart manually.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

{%- for btype in ["plain", "regex", "wildcard"] %}
{%-   if pihole.blacklist.present[btype] %}

PiHole wanted {{ btype }} blacklist entries are absent:
  pihole.blacklist_absent:
    - domains: {{ pihole.blacklist.present[btype] | json }}
{%-     if btype != "plain" %}
    - {{ btype }}: true
{%-     endif %}
{%-   endif %}
{%- endfor %}
