# vim: ft=sls

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_package_install = tplroot ~ ".package.install" %}
{%- set sls_service_running = tplroot ~ ".service.running" %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

include:
  - {{ sls_package_install }}
  - {{ sls_service_running }}

{%- if pihole.custom_dns.present %}

PiHole custom DNS A/AAAA entries are managed:
  pihole.custom_dns:
    - names:
{%-   for domain, target in pihole.custom_dns.present.items() %}
      - {{ domain }}:
        - ip: {{ target }}
{%-   endfor %}
    - require:
      - sls: {{ sls_package_install }}
    - watch_in:
      - PiHole is running
{%- endif %}

{%- if pihole.custom_dns.absent %}

PiHole unwanted custom DNS A/AAAA entries are absent:
  pihole.custom_dns_absent:
    - names:
{%-   for domain in pihole.custom_dns.absent %}
{%-     if domain is mapping %}
      - {{ domain | first }}:
        - ip: {{ domain[domain | first] }}
{%-     else %}
      - {{ domain }}
{%-     endif %}
{%-   endfor %}
    - require:
      - sls: {{ sls_package_install }}
    - watch_in:
      - PiHole is running
{%- endif %}
