# vim: ft=sls

{#-
    Manages the PiHole API password, the `pihole.toml` configuration as well as the dnsmasq one, if configured.
    Has a dependency on `pihole.package`_.
#}

include:
  - .secrets
  - .file
