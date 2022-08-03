# -*- coding: utf-8 -*-
# vim: ft=sls

{%- set tplroot = tpldir.split('/')[0] %}
{%- from tplroot ~ "/map.jinja" import mapdata as pihole with context %}

pihole-service-clean-service-dead:
  service.dead:
    - name: {{ pihole.lookup.service.name }}
    - enable: False
