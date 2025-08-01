Available states
----------------

The following states are found in this formula:

.. contents::
   :local:


``pihole``
^^^^^^^^^^
*Meta-state*.

This installs the pihole package,
manages the pihole configuration file,
adlists, blacklists, custom CNAME and DNS config,
groups, whitelists, then starts the pihole-FTL service.


``pihole.package``
^^^^^^^^^^^^^^^^^^
Installs PiHole only and syncs the custom modules found in this formula.

Warning:
  This pipes the output fetching the installation script from the URL in
  ``pihole.lookup.setup_sh`` into a root shell because the setup is sadly
  rather the antithesis of straightforward to reproduce with Salt.
  It's possible to provide a local replacement
  for the script by overriding ``pihole.lookup.setup_sh`` e.g. to a salt:// URI.


``pihole.config``
^^^^^^^^^^^^^^^^^
Manages the PiHole API password, the `pihole.toml` configuration as well as the dnsmasq one, if configured.
Has a dependency on `pihole.package`_.


``pihole.config.file``
^^^^^^^^^^^^^^^^^^^^^^
Manages the `pihole.toml` configuration.

If `pihole:config:dnsmasq` is set, additionally manages a dnsmasq configuration file.
This is usually not necessary, just set `pihole:config:app:misc:dnsmasq_lines`.
If used anyways, this formula ensures `pihole:config:app:misc:etc_dnsmasq_d` is enabled.


``pihole.config.secrets``
^^^^^^^^^^^^^^^^^^^^^^^^^
Manages the PiHole API password.
If none was provided in `pihole:secrets:api_password:(pillar|plaintext)`
and it is unset when rendering this state, a random one is generated
to ensure it is set.


``pihole.cert``
^^^^^^^^^^^^^^^
Generates a TLS certificate + key for PiHole.
Depends on `pihole.package`_.


``pihole.adlist``
^^^^^^^^^^^^^^^^^
Manages PiHole adlists and updates the gravity database.
Has a dependency on `pihole.service`_.


``pihole.blacklist``
^^^^^^^^^^^^^^^^^^^^
Manages PiHole blacklist entries.
Has a dependency on `pihole.service`_.


``pihole.custom_cname``
^^^^^^^^^^^^^^^^^^^^^^^
Manages PiHole custom CNAME entries.
Has a dependency on `pihole.service`_.


``pihole.custom_dns``
^^^^^^^^^^^^^^^^^^^^^
Manages PiHole local DNS A/AAAA entries.
Has a dependency on `pihole.service`_.


``pihole.group``
^^^^^^^^^^^^^^^^
Manages PiHole groups.
Has a dependency on `pihole.service`_.


``pihole.whitelist``
^^^^^^^^^^^^^^^^^^^^
Manages PiHole whitelist entries.
Has a dependency on `pihole.service`_.


``pihole.service``
^^^^^^^^^^^^^^^^^^
Starts the pihole-FTL service and enables it at boot time.
Has a dependency on `pihole.config`_.


``pihole.clean``
^^^^^^^^^^^^^^^^
*Meta-state*.

Undoes some operations performed in the ``pihole`` meta-state
in reverse order, i.e.
removes generated TLS certificates,
stops the service,
removes the configuration.
The package cannot be uninstalled automatically.


``pihole.package.clean``
^^^^^^^^^^^^^^^^^^^^^^^^
**This state will fail.** PiHole currently cannot be removed without user interaction.
Has a dependency on `pihole.config.clean`_.


``pihole.config.clean``
^^^^^^^^^^^^^^^^^^^^^^^
Removes the PiHole, pihole-FTL and custom dnsmasq configurations and has a
dependency on `pihole.service.clean`_.


``pihole.cert.clean``
^^^^^^^^^^^^^^^^^^^^^
Removes generated PiHole TLS certificate + key.
Depends on `pihole.service.clean`_.


``pihole.adlist.clean``
^^^^^^^^^^^^^^^^^^^^^^^
Removes managed PiHole adlists.
This does not restart PiHole on its own. To apply, you will need to restart manually.


``pihole.blacklist.clean``
^^^^^^^^^^^^^^^^^^^^^^^^^^
Removes managed PiHole blacklist entries.
This does not restart PiHole on its own. To apply, you will need to restart manually.


``pihole.custom_cname.clean``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Removes managed PiHole custom CNAME entries.
This does not restart PiHole on its own. To apply, you will need to restart manually.


``pihole.custom_dns.clean``
^^^^^^^^^^^^^^^^^^^^^^^^^^^
Removes managed PiHole local DNS A/AAAA entries.
This does not restart PiHole on its own. To apply, you will need to restart manually.


``pihole.group.clean``
^^^^^^^^^^^^^^^^^^^^^^
Removes managed PiHole groups.
This does not restart PiHole on its own. To apply, you will need to restart manually.


``pihole.whitelist.clean``
^^^^^^^^^^^^^^^^^^^^^^^^^^
Removes managed PiHole whitelist entries.
This does not restart PiHole on its own. To apply, you will need to restart manually.


``pihole.service.clean``
^^^^^^^^^^^^^^^^^^^^^^^^
Stops the pihole-FTL service and disables it at boot time.


