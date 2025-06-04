# vim: ft=sls

{#-
    *Meta-state*.

    This installs the pihole package,
    manages the pihole configuration file,
    adlists, blacklists, custom CNAME and DNS config,
    groups, whitelists, then starts the pihole-FTL service.
#}

include:
  - .package
  - .config
  - .cert
  - .adlist
  - .blacklist
  - .custom_cname
  - .custom_dns
  - .group
  - .whitelist
  - .service
