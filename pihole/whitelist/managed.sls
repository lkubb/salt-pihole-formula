# vim: ft=sls

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_package_install = tplroot ~ ".package.install" %}
{%- set sls_service_running = tplroot ~ ".service.running" %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

include:
  - {{ sls_package_install }}
  - {{ sls_service_running }}

{%- for wtype in ["plain", "regex", "wildcard"] %}
{%-   if pihole.whitelist.present[wtype] %}

PiHole {{ wtype }} whitelist entries are managed:
  pihole.whitelist:
    - domains: {{ pihole.whitelist.present[wtype] | json }}
{%-     if wtype != "plain" %}
    - {{ wtype }}: true
{%-     endif %}
    - require:
      - sls: {{ sls_package_install }}
    - watch_in:
      - PiHole is running
{%-   endif %}

{%-   if pihole.whitelist.absent[wtype] %}

PiHole unwanted {{ wtype }} whitelist entries are absent:
  pihole.whitelist_absent:
    - domains: {{ pihole.whitelist.absent[wtype] | json }}
{%-     if wtype != "plain" %}
    - {{ wtype }}: true
{%-     endif %}
    - require:
      - sls: {{ sls_package_install }}
    - watch_in:
      - PiHole is running
{%-   endif %}
{%- endfor %}
