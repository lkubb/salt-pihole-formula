# vim: ft=sls

{#-
    *Meta-state*.

    Undoes some operations performed in the ``pihole`` meta-state
    in reverse order, i.e.
    removes TLS configuration from lighttpd,
    stops the service,
    removes the configuration.
    The package cannot be uninstalled automatically.
#}

include:
  - .tls.clean
  - .cert.clean
  - .service.clean
  - .config.clean
  - .package.clean
