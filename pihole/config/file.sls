# vim: ft=sls

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_package_install = tplroot ~ ".package.install" %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}
{%- from tplroot ~ "/libtofsstack.jinja" import files_switch with context %}

include:
  - {{ sls_package_install }}

PiHole configuration is managed:
  file.managed:
    - name: {{ pihole.lookup.config }}
    - source: {{ files_switch(
                    ["setupVars.conf", "setupVars.conf.j2"],
                    config=pihole,
                    lookup="PiHole configuration is managed",
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

PiHole FTL configuration is managed:
  file.managed:
    - name: {{ salt["file.dirname"](pihole.lookup.config) | path_join("pihole-FTL.conf") }}
    - source: {{ files_switch(["pihole-FTL.conf", "pihole-FTL.conf.j2"],
                              lookup="PiHole FTL configuration is managed"
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

Custom dnsmasq configuration is managed:
  file.managed:
    - name: {{ pihole.lookup.config_dnsmasq }}
    - source: {{ files_switch(["dnsmasq.conf", "dnsmasq.conf.j2"],
                              lookup="Custom dnsmasq configuration is managed"
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
