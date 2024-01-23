.. _readme:

PiHole Formula
==============

|img_sr| |img_pc|

.. |img_sr| image:: https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg
   :alt: Semantic Release
   :scale: 100%
   :target: https://github.com/semantic-release/semantic-release
.. |img_pc| image:: https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white
   :alt: pre-commit
   :scale: 100%
   :target: https://github.com/pre-commit/pre-commit

Manage PiHole with Salt.

This formula also provides a custom execution and state module to manage PiHole beyond the setup.

Mind that automatic testing is currently not implemented, even if suggested otherwise from forking the official template formula.

.. contents:: **Table of Contents**
   :depth: 1

General notes
-------------

See the full `SaltStack Formulas installation and usage instructions
<https://docs.saltstack.com/en/latest/topics/development/conventions/formulas.html>`_.

If you are interested in writing or contributing to formulas, please pay attention to the `Writing Formula Section
<https://docs.saltstack.com/en/latest/topics/development/conventions/formulas.html#writing-formulas>`_.

If you want to use this formula, please pay attention to the ``FORMULA`` file and/or ``git tag``,
which contains the currently released version. This formula is versioned according to `Semantic Versioning <http://semver.org/>`_.

See `Formula Versioning Section <https://docs.saltstack.com/en/latest/topics/development/conventions/formulas.html#versioning>`_ for more details.

If you need (non-default) configuration, please refer to:

- `how to configure the formula with map.jinja <map.jinja.rst>`_
- the ``pillar.example`` file
- the `Special notes`_ section

Special notes
-------------


Configuration
-------------
An example pillar is provided, please see `pillar.example`. Note that you do not need to specify everything by pillar. Often, it's much easier and less resource-heavy to use the ``parameters/<grain>/<value>.yaml`` files for non-sensitive settings. The underlying logic is explained in `map.jinja`.


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
Also manages the lighttpd server regarding TLS configuration.


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
Manages the PiHole, pihole-FTL and custom dnsmasq configurations.
Has a dependency on `pihole.package`_.


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


``pihole.tls``
^^^^^^^^^^^^^^
Configure and enable TLS for PiHole (lighttpd).
Has a dependency on `pihole.package`_.


``pihole.clean``
^^^^^^^^^^^^^^^^
*Meta-state*.

Undoes some operations performed in the ``pihole`` meta-state
in reverse order, i.e.
removes TLS configuration from lighttpd,
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


``pihole.tls.clean``
^^^^^^^^^^^^^^^^^^^^
Removes TLS configuration from lighttpd.



Contributing to this repo
-------------------------

Commit messages
^^^^^^^^^^^^^^^

**Commit message formatting is significant!**

Please see `How to contribute <https://github.com/saltstack-formulas/.github/blob/master/CONTRIBUTING.rst>`_ for more details.

pre-commit
^^^^^^^^^^

`pre-commit <https://pre-commit.com/>`_ is configured for this formula, which you may optionally use to ease the steps involved in submitting your changes.
First install  the ``pre-commit`` package manager using the appropriate `method <https://pre-commit.com/#installation>`_, then run ``bin/install-hooks`` and
now ``pre-commit`` will run automatically on each ``git commit``. ::

  $ bin/install-hooks
  pre-commit installed at .git/hooks/pre-commit
  pre-commit installed at .git/hooks/commit-msg

State documentation
~~~~~~~~~~~~~~~~~~~
There is a script that semi-autodocuments available states: ``bin/slsdoc``.

If a ``.sls`` file begins with a Jinja comment, it will dump that into the docs. It can be configured differently depending on the formula. See the script source code for details currently.

This means if you feel a state should be documented, make sure to write a comment explaining it.

Testing
-------

Linux testing is done with ``kitchen-salt``.

Requirements
^^^^^^^^^^^^

* Ruby
* Docker

.. code-block:: bash

   $ gem install bundler
   $ bundle install
   $ bin/kitchen test [platform]

Where ``[platform]`` is the platform name defined in ``kitchen.yml``,
e.g. ``debian-9-2019-2-py3``.

``bin/kitchen converge``
^^^^^^^^^^^^^^^^^^^^^^^^

Creates the docker instance and runs the ``pihole`` main state, ready for testing.

``bin/kitchen verify``
^^^^^^^^^^^^^^^^^^^^^^

Runs the ``inspec`` tests on the actual instance.

``bin/kitchen destroy``
^^^^^^^^^^^^^^^^^^^^^^^

Removes the docker instance.

``bin/kitchen test``
^^^^^^^^^^^^^^^^^^^^

Runs all of the stages above in one go: i.e. ``destroy`` + ``converge`` + ``verify`` + ``destroy``.

``bin/kitchen login``
^^^^^^^^^^^^^^^^^^^^^

Gives you SSH access to the instance for manual testing.

Todo
----
* `Automatically <https://github.com/jacklul/pihole-updatelists>`_ import `meta-lists <https://v.firebog.net/hosts/lists.php?type=tick>`_ and `whitelists <https://github.com/anudeepND/whitelist/>`_
