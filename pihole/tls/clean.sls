# vim: ft=sls

{#-
    Removes TLS configuration from lighttpd.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_package_install = tplroot ~ ".package.install" %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

{%- if pihole.tls.enabled %}

lighttpd is not setup for TLS:
  file.managed:
    - name: /etc/lighttpd/external.conf
    - contents: ''
    - mode: '0644'
    - user: root
    - group: {{ pihole.lookup.rootgroup }}
    - makedirs: true
    - template: jinja
{%- endif %}
