# vim: ft=sls

{#-
    Removes managed PiHole custom CNAME entries.
    This does not restart PiHole on its own. To apply, you will need to restart manually.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

{%- if pihole.custom_cname.present %}

PiHole wanted CNAME entries are absent:
  pihole.cname_absent:
    - names:
{%-   for cname, target in pihole.custom_cname.present.items() %}
      - {{ cname }}:
        - target: {{ target }}
{%-   endfor %}
{%- endif %}
