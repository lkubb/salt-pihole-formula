# vim: ft=sls

{#-
    Removes managed PiHole whitelist entries.
    This does not restart PiHole on its own. To apply, you will need to restart manually.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

{%- for wtype in ["plain", "regex", "wildcard"] %}
{%-   if pihole.whitelist.present[wtype] %}

PiHole wanted {{ wtype }} whitelist entries are absent:
  pihole.whitelist_absent:
    - domains: {{ pihole.whitelist.present[wtype] | json }}
{%-     if wtype != "plain" %}
    - {{ wtype }}: true
{%-     endif %}
{%-   endif %}
{%- endfor %}
