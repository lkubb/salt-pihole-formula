# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}
{%- from tplroot ~ "/libtofs.jinja" import files_switch with context %}

PiHole initial setupVars are present:
  file.managed:
    - name: {{ pihole.lookup.config }}
    - source: {{ files_switch(['setupVars.conf', 'setupVars.conf.j2'],
                              lookup='PiHole initial setupVars are present'
                 )
              }}
    - makedirs: true
    - user: root
    - group: {{ pihole.lookup.rootgroup }}
    - mode: '0644'
    - template: jinja
    # config is managed in config, this is just here to make the unattended
    # installation work correctly
    - replace: false
    - context:
        pihole: {{ pihole | json }}

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
      - PiHole initial setupVars are present

Custom PiHole modules are synced:
  saltutil.sync_all:
    - refresh: true
