# vim: ft=sls

{#-
    **This state will fail.** PiHole currently cannot be removed without user interaction.
    Has a dependency on `pihole.config.clean`_.
#}

{%- set tplroot = tpldir.split("/")[0] %}
{%- set sls_config_clean = tplroot ~ ".config.clean" %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

include:
  - {{ sls_config_clean }}

PiHole is removed:
  test.fail_without_changes:
    - name: PiHole currently cannot be removed without user interaction.
