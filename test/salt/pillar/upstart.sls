# vim: ft=yaml
---
pihole:
  lookup:
    master: template-master
    # Just for testing purposes
    winner: lookup
    added_in_lookup: lookup_value
    config: '/etc/pihole/setupVars.conf'
    service:
      name: pihole-FTL
    config_dnsmasq: /etc/dnsmasq.d/05-salt.conf
    lighttpd_openssl: lighttpd-mod-openssl
    setup_sh: https://raw.githubusercontent.com/pi-hole/pi-hole/master/automated%20install/basic-install.sh
  adlists:
    absent: []
    present: []
  autoupdate: true
  blacklist:
    absent:
      plain: []
      regex: []
      wildcard: []
    present:
      plain: []
      regex: []
      wildcard: []
  config:
    app:
      admin_email: ''
      api_exclude_clients: []
      api_exclude_domains: []
      api_query_log_show: all
      blocking_enabled: true
      cache_size: 10000
      dhcp:
        active: false
        domain: null
        end: null
        ipv6: null
        leasetime: null
        rapid_commit: null
        router: null
        start: null
      dns_bogus_priv: true
      dns_fqdn_required: true
      dns_upstream:
        - 1.1.1.1
        - 1.0.0.1
      dnsmasq_listening: local
      dnssec: false
      install_web_interface: true
      install_web_server: true
      ipv4_address: null
      ipv6_address: null
      lighttpd_enabled: true
      pihole_interface: null
      query_logging: true
      rev_server:
        cidr: null
        domain: null
        enabled: false
        target: null
      webpassword: null
      webpassword_pillar: null
      webtheme: default
      webuiboxedlayout: boxed
    dnsmasq: {}
    ftl:
      privacylevel: 0
  custom_cname:
    absent: []
    present: {}
  custom_dns:
    absent: []
    present: {}
  groups:
    absent: []
    present: []
  tls:
    enabled: false
    hostname: ''
    hsts: false
    pemfile: ''
    privkey: ''
  whitelist:
    absent:
      plain: []
      regex: []
      wildcard: []
    present:
      plain: []
      regex: []
      wildcard: []

  tofs:
    # The files_switch key serves as a selector for alternative
    # directories under the formula files directory. See TOFS pattern
    # doc for more info.
    # Note: Any value not evaluated by `config.get` will be used literally.
    # This can be used to set custom paths, as many levels deep as required.
    files_switch:
      - any/path/can/be/used/here
      - id
      - roles
      - osfinger
      - os
      - os_family
    # All aspects of path/file resolution are customisable using the options below.
    # This is unnecessary in most cases; there are sensible defaults.
    # Default path: salt://< path_prefix >/< dirs.files >/< dirs.default >
    #         I.e.: salt://pihole/files/default
    # path_prefix: template_alt
    # dirs:
    #   files: files_alt
    #   default: default_alt
    # The entries under `source_files` are prepended to the default source files
    # given for the state
    # source_files:
    #   pihole-config-file-file-managed:
    #     - 'example_alt.tmpl'
    #     - 'example_alt.tmpl.jinja'

    # For testing purposes
    source_files:
      pihole-config-file-file-managed:
        - 'example.tmpl.jinja'

  # Just for testing purposes
  winner: pillar
  added_in_pillar: pillar_value
