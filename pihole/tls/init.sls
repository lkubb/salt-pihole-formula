# vim: ft=sls

{#-
    Configure and enable TLS for PiHole (lighttpd).
    Has a dependency on `pihole.package`_.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_package_install = tplroot ~ ".package.install" %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}
{%- from tplroot ~ "/libtofs.jinja" import files_switch with context %}

include:
  - {{ sls_package_install }}

{%- if pihole.tls.enabled %}

lighttpd openssl module is present:
  pkg.installed:
    - name: {{ pihole.lookup.lighttpd_openssl }}

lighttpd is setup for TLS:
  file.managed:
    - name: /etc/lighttpd/external.conf
    - source: {{ files_switch(["tls.conf", "tls.conf.j2"],
                              lookup="lighttpd is setup for TLS"
                 )
              }}
    - mode: '0644'
    - user: root
    - group: {{ pihole.lookup.rootgroup }}
    - makedirs: true
    - template: jinja
    - require:
      - lighttpd openssl module is present
      - sls: {{ sls_package_install }}
    - context:
        pihole: {{ pihole | json }}

lighttpd is running:
  service.running:
    - name: lighttpd
    - watch:
      - lighttpd is setup for TLS
{%- endif %}
