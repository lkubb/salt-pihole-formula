# vim: ft=sls

{#-
    *Meta-state*.

    Undoes some operations performed in the ``pihole`` meta-state
    in reverse order, i.e.
    removes generated TLS certificates,
    stops the service,
    removes the configuration.
    The package cannot be uninstalled automatically.
#}

include:
  - .cert.clean
  - .service.clean
  - .config.clean
  - .package.clean
