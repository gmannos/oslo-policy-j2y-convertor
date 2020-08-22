========================
oslopolicy-j2y-convertor
========================

::

   oslopolicy-j2y-convertor [-h] [--config-dir DIR] [--config-file PATH]
                            [--namespace NAMESPACE]
                            [--policy-file POLICY_FILE]
                            [--output-file OUTPUT_FILE]


The ``oslopolicy-j2y-convertor`` tool can be used to convert the json
policy file to yaml format.

OpenStack nova switched to the new policy with new defaults and scope feature
from keystone in Ussuri cycle( `nova 21.0.0 <https://releases.openstack.org/ussuri/index.html#ussuri-nova>`_). But few deployement used to generate the policy file in json format via `oslopolicy-sample-generator <https://docs.openstack.org/oslo.policy/latest/cli/oslopolicy-sample-generator.html>`_ tool started failing.
Refer `this bug <https://bugs.launchpad.net/nova/+bug/1875418>`_ for details.

It is recommended to switch to yaml formatted policy file where you can comemntout the rule. You can generate the new yaml format policy file form this tool `oslopolicy-sample-generator <https://docs.openstack.org/oslo.policy/latest/cli/oslopolicy-sample-generator.html>`_ or convert the existing json policy file via this tool. This tool make sure it does not break the deployement and give you opportunity of switching to new policy when you have time. This tool does the following:

* Comment out any rules that match the default from policy-in-code.
* Keep Rule uncommented if rule is overridden.
* Does not auto add the deprecated rules in file unless it not already
  present in file.
* Keep any extra rules or already exist depreacated rules uncommented
  but at the end of file with warning text. 

Examples
--------

To convert JSON formatted policy file to YAML format directly to a file:

.. code-block:: bash

   oslopolicy-convert-json-to-yaml --namespace nova \
     --policy-file policy.json \
     --output-file policy.yaml
