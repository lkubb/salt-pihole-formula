# vim: ft=sls

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_package_install = tplroot ~ ".package.install" %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

include:
  - {{ sls_package_install }}

{%- if pihole.cert.generate %}

PiHole certificate private key is managed:
  x509.private_key_managed:
    - name: {{ pihole.lookup.cert.privkey }}
    - algo: rsa
    - keysize: 2048
    - new: true
{%-   if salt["file.file_exists"](pihole.lookup.cert.privkey) %}
    - prereq:
      - PiHole certificate is managed
{%-   endif %}
    - makedirs: true
    - user: root
    - group: {{ pihole.lookup.rootgroup }}
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
    - subjectAltName:
      - dns: {{ pihole.cert.cn or ([grains.fqdn] + grains.fqdns) | reject("==", "localhost.localdomain") | first | d(grains.id) }}
      - ip: {{ (grains.get("ip4_interfaces", {}).get("eth0", [""]) | first) or (grains.get("ipv4") | reject("==", "127.0.0.1") | first) }}
{%-   endif %}
    - CN: {{ pihole.cert.cn or ([grains.fqdn] + grains.fqdns) | reject("==", "localhost.localdomain") | first | d(grains.id) }}
    - mode: '0640'
    - user: root
    - group: {{ pihole.lookup.rootgroup }}
    - makedirs: true
    - append_certs: {{ pihole.cert.intermediate | json }}
    - days_remaining: {{ pihole.cert.days_remaining }}
    - days_valid: {{ pihole.cert.days_valid }}
    - require:
      - sls: {{ sls_package_install }}
{%-   if not salt["file.file_exists"](pihole.lookup.cert.privkey) %}
      - PiHole certificate private key is managed
{%-   endif %}
{%- endif %}
