# vim: ft=sls

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_package_install = tplroot ~ ".package.install" %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}
{%- from tplroot ~ "/libtofsstack.jinja" import files_switch with context %}

include:
  - {{ sls_package_install }}

PiHole configuration is managed:
  pihole.config_managed:
    - config: {{ pihole.config.app | json }}
    - require:
      - PiHole is installed

{#-
    This is not needed anymore, it can be configured via pihole.toml
    in misc.dnsmasq_lines. If used anyways, it needs misc.etc_dnsmasq_d enabled.
#}

Custom dnsmasq configuration is managed:
{%- if pihole.config.dnsmasq %}
  file.managed:
    - name: {{ pihole.lookup.config_dnsmasq }}
    - source: {{ files_switch(
                    ["dnsmasq.conf", "dnsmasq.conf.j2"],
                    config=pihole,
                    lookup="Custom dnsmasq configuration is managed",
                 )
              }}
    - mode: '0644'
    - user: root
    - group: {{ pihole.lookup.rootgroup }}
    - makedirs: true
    - template: jinja
    - require:
      - PiHole is installed
    - context:
        pihole: {{ pihole | json }}

{%- else %}
  file.absent:
    - name: {{ pihole.lookup.config_dnsmasq }}
{%- endif %}
