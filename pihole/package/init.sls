# vim: ft=sls

{#-
    Installs PiHole only and syncs the custom modules found in this formula.

    Warning:
      This pipes the output fetching the installation script from the URL in
      ``pihole.lookup.setup_sh`` into a root shell because the setup is sadly
      rather the antithesis of straightforward to reproduce with Salt.
      It's possible to provide a local replacement
      for the script by overriding ``pihole.lookup.setup_sh`` e.g. to a salt:// URI.
#}

include:
  - .install
