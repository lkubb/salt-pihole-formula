# vim: ft=sls

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_package_install = tplroot ~ ".package.install" %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}
{%- from tplroot ~ "/libtofsstack.jinja" import files_switch with context %}

include:
  - {{ sls_package_install }}

{%- if pihole.cert.generate %}

PiHole certificate private key is managed:
  x509.private_key_managed:
    - name: {{ pihole.lookup.cert.privkey }}
    - algo: {{ pihole.cert.algo }}
    - keysize: {{ pihole.cert.keysize }}
    - new: true
{%-   if salt["file.file_exists"](pihole.lookup.cert.privkey) %}
    - prereq:
      - PiHole certificate is managed
{%-   endif %}
    - makedirs: true
    - user: {{ pihole.lookup.user }}
    - group: {{ pihole.lookup.group }}
    - require:
      - sls: {{ sls_package_install }}

PiHole certificate is managed:
  x509.certificate_managed:
    - name: {{ pihole.lookup.cert.cert }}
    - ca_server: {{ pihole.cert.ca_server or "null" }}
    - signing_policy: {{ pihole.cert.signing_policy or "null" }}
    - signing_cert: {{ pihole.cert.signing_cert or "null" }}
    - signing_private_key: {{ pihole.cert.signing_private_key or
                              (pihole.lookup.cert.privkey if not pihole.cert.ca_server and not pihole.cert.signing_cert else "null") }}
    - private_key: {{ pihole.lookup.cert.privkey }}
    - authorityKeyIdentifier: keyid:always
    - basicConstraints: critical, CA:false
    - subjectKeyIdentifier: hash
{%-   if pihole.cert.san %}
    - subjectAltName: {{ pihole.cert.san | json }}
{%-   else %}
{%-     set dnssans = [] %}
{%-     set ipsans = [] %}
{%-     for domain in [pihole.config.app.webserver.domain, pihole.cert.cn] + [grains.get("fqdn")] + grains.get("fqdns", []) %}
{%-       if domain and "localhost" not in domain and domain not in dnssans %}
{%-         do dnssans.append(domain) %}
{%-       endif %}
{%-     endfor %}
{%-     for ip in grains.get("ipv4", []) %}
{%-       if ip and not ip.startswith("127.") and ip not in ipsans %}
{%-         do ipsans.append(ip) %}
{%-       endif %}
{%-     endfor %}
    - subjectAltName:
{%-     for dns in dnssans %}
      - dns: {{ dns }}
{%-     endfor %}
{%-     for ip in ipsans %}
      - ip: {{ ip }}
{%-     endfor %}
{%-   endif %}
    - CN: {{ pihole.cert.cn or pihole.config.app.webserver.domain or grains.get("fqdn") or grains.id }}
    - mode: '0600'
    - user: {{ pihole.lookup.user }}
    - group: {{ pihole.lookup.group }}
    - makedirs: true
    - append_certs: {{ pihole.cert.intermediate | json }}
    - days_remaining: {{ pihole.cert.days_remaining }}
    - days_valid: {{ pihole.cert.days_valid }}
    - require:
      - sls: {{ sls_package_install }}
{%-   if not salt["file.file_exists"](pihole.lookup.cert.privkey) %}
      - PiHole certificate private key is managed
{%-   endif %}

PiHole merged pem file is managed:
  file.managed:
    - name: {{ pihole.config.app.webserver.tls.cert }}
    - source: {{ files_switch(
                    ["merged_cert.pem", "merged_cert.pem.j2"],
                    config=pihole,
                    lookup="PiHole merged pem file is managed",
                 )
              }}
    - template: jinja
    - mode: '0600'
    - user: {{ pihole.lookup.user }}
    - group: {{ pihole.lookup.group }}
    - require:
      - x509: {{ pihole.lookup.cert.privkey }}
      - x509: {{ pihole.lookup.cert.cert }}
    - context:
        pihole: {{ pihole | json }}
{%- endif %}
