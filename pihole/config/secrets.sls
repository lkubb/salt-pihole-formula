# vim: ft=sls

{#-
    Manages the PiHole API password.
    If none was provided in `pihole:secrets:api_password:(pillar|plaintext)`
    and it is unset when rendering this state, a random one is generated
    to ensure it is set.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_package_install = tplroot ~ ".package.install" %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}
{%- from tplroot ~ "/libtofsstack.jinja" import files_switch with context %}

include:
  - {{ sls_package_install }}


PiHole API password is managed:
  pihole.api_password_managed:
    - pillar: {{ pihole.secrets.api_password.pillar | json }}
    - password: {{ pihole.secrets.api_password.plaintext | json }}
    - require:
      - sls: {{ sls_package_install }}

PiHole TOTP secret is managed:
  pihole.totp_secret_managed:
    - pillar: {{ pihole.secrets.totp_secret.pillar | json }}
    - secret: {{ pihole.secrets.totp_secret.plaintext | json }}
    - force: {{ pihole.secrets.totp_secret.force | json }}
    - require:
      - sls: {{ sls_package_install }}
