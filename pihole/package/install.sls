# vim: ft=sls

{%- set tplroot = tpldir.split("/")[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}
{%- from tplroot ~ "/libtofsstack.jinja" import files_switch with context %}

Toml lib is available for PiHole config:
  pip.installed:
    - name: toml
    - reload_modules: true
    - unless:
      - '{{ (grains.pythonversion[1] > 10) | lower }}'


PiHole user/group are present:
  group.present:
    - name: {{ pihole.lookup.group }}
  user.present:
    - name: {{ pihole.lookup.user }}
    - createhome: false
    - shell: /usr/sbin/nologin
    - system: true
    - usergroup: false
    - gid: {{ pihole.lookup.group }}
    - require:
      - group: {{ pihole.lookup.group }}

PiHole initial config is present:
  file.serialize:
    - name: {{ pihole.lookup.config }}
    - serializer: toml
    - dataset: {{ pihole.config.app | json }}
    - makedirs: true
    - user: {{ pihole.lookup.user }}
    - group: {{ pihole.lookup.group }}
    - mode: '0640'
    - require:
      - pip: toml
      - user: {{ pihole.lookup.user }}
    # config is managed in config, this is just here to make the unattended
    # installation work correctly.
    # file.serialize does not have replace: false
    - unless:
      - fun: file.file_exists
        path: {{ pihole.lookup.config }}

# Piping curl to bash as root? No worries, mate!
# I wanted this to run outside a container and the setup is rather the
# antithesis of straightforward. It's possible to provide a local replacement
# for the script by overriding `pihole.lookup.setup_sh` e.g. to a salt:// URI.
PiHole is installed:
  cmd.script:
    - source: {{ pihole.lookup.setup_sh }}
    - args: --unattended
    - creates: /opt/pihole
    - require:
      - PiHole initial config is present

Custom PiHole modules are synced:
  saltutil.sync_all:
    - refresh: true
    - unless:
      - '{{ ("pihole" in salt["saltutil.list_extmods"]().get("states", [])) | lower }}'

{%- if pihole.autoupdate %}

Pihole is up to date:
  pihole.uptodate
{%- endif %}
