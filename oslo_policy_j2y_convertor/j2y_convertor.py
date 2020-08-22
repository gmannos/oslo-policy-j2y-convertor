import logging
import sys
import textwrap
import warnings

from oslo_config import cfg
from oslo_serialization import jsonutils
import stevedore

from oslo_policy import generator
from oslo_policy import policy

LOG = logging.getLogger(__name__)

CONVERT_OPTS = [
    cfg.StrOpt('output-file',
               help='Path of the file to write to. Defaults to stdout.'),
    cfg.MultiStrOpt('namespace',
                    required=True,
                    help='Option namespace(s) under "oslo.policy.policies" in '
                        'which to query for options.'),
    cfg.StrOpt('policy-file',
               required=True,
               help='Path to the policy file which need to be converted to yaml format.')
]


def _format_rule_default_yaml(default, include_help=True, comment_rule=True,
                              add_deprecated_rules=True):
    """Create a yaml node from policy.RuleDefault or policy.DocumentedRuleDefault.

    :param default: A policy.RuleDefault or policy.DocumentedRuleDefault object
    :param comment_rule: By default rules will be commentout out in generated
                         yaml format text. If you want to keep few or all rules
                         uncommented then pass this arg as False.
    :param add_deprecated_rules: Whether to add the deprecated rules in format
                                 text.
    :returns: A string containing a yaml representation of the RuleDefault
    """
    text = ('"%(name)s": "%(check_str)s"\n' %
            {'name': default.name,
             'check_str': default.check_str})

    if include_help:
        op = ""
        if hasattr(default, 'operations'):
            for operation in default.operations:
                op += ('# %(method)s  %(path)s\n' %
                       {'method': operation['method'],
                        'path': operation['path']})
        intended_scope = ""
        if getattr(default, 'scope_types', None) is not None:
            intended_scope = (
                '# Intended scope(s): ' + ', '.join(default.scope_types) + '\n'
            )
        comment =  '#' if comment_rule else ''
        text = ('%(help)s\n%(op)s%(scope)s%(comment)s%(text)s\n' %
                {'help': generator._format_help_text(default.description),
                 'op': op,
                 'scope': intended_scope,
                 'comment': comment,
                 'text': text})

    if add_deprecated_rules and default.deprecated_for_removal:
        text = (
            '# DEPRECATED\n# "%(name)s" has been deprecated since '
            '%(since)s.\n%(reason)s\n%(text)s'
        ) % {'name': default.name,
             'check_str': default.check_str,
             'since': default.deprecated_since,
             'reason': generator._format_help_text(default.deprecated_reason),
             'text': text}
    elif add_deprecated_rules and default.deprecated_rule:
        # This issues a deprecation warning but aliases the old policy name
        # with the new policy name for compatibility.
        deprecated_text = (
            'DEPRECATED\n"%(old_name)s":"%(old_check_str)s" has been '
            'deprecated since %(since)s in favor of '
            '"%(name)s":"%(check_str)s".\n%(reason)s'
        ) % {'old_name': default.deprecated_rule.name,
             'old_check_str': default.deprecated_rule.check_str,
             'since': default.deprecated_since,
             'name': default.name,
             'check_str': default.check_str,
             'reason': default.deprecated_reason}

        if default.name != default.deprecated_rule.name:
            text = (
                '%(text)s%(deprecated_text)s\n"%(old_name)s": "rule:%(name)s"'
                '\n'
            ) % {'text': text,
                 'deprecated_text': _generator.format_help_text(deprecated_text),
                 'old_name': default.deprecated_rule.name,
                 'name': default.name}
        else:
            text = (
                '%(text)s%(deprecated_text)s\n'
            ) % {'text': text,
                 'deprecated_text': _generator.format_help_text(deprecated_text)}

    return text


def convert_policy_json_to_yaml(args=None, conf=None):
    logging.basicConfig(level=logging.WARN)
    # Allow the caller to pass in a local conf object for unit testing
    if conf is None:
        conf = cfg.CONF
    conf.register_cli_opts(CONVERT_OPTS)
    conf.register_opts(CONVERT_OPTS)
    conf(args)
    generator._check_for_namespace_opt(conf)
    with open(conf.policy_file, 'r') as rule_data:
        file_policies = jsonutils.loads(rule_data.read())
    yaml_format_rules = []
    mgr = stevedore.named.NamedExtensionManager(
        'oslo.policy.policies',
        names=conf.namespace,
        on_load_failure_callback=generator.on_load_failure_callback,
        invoke_on_load=True)
    opts = {ep.name: ep.obj for ep in mgr}

    default_policies = opts
    for section in sorted(default_policies.keys()):
        default_rules = default_policies[section]
        for default_rule in default_rules:
            if default_rule.name in file_policies:
                file_rule_check_str = file_policies.pop(default_rule.name)
                # Few rules might be still RuleDefault object so let's prepare
                # empty 'operations' list for those.
                operations = [            {
                    'method': '',
                    'path': ''
                }]
                if hasattr(default_rule, 'operations'):
                    operations=  default_rule.operations
                # Converting json file rules to DocumentedRuleDefault rules so
                # that we can covert the json file to yaml including
                # descriptions which is what 'oslopolicy-sample-generator'
                # tool does.
                file_rule = policy.DocumentedRuleDefault(
                    default_rule.name,
                    file_rule_check_str,
                    default_rule.description,
                    operations,
                    default_rule.deprecated_rule,
                    default_rule.deprecated_for_removal,
                    default_rule.deprecated_reason,
                    default_rule.deprecated_since,
                    scope_types=default_rule.scope_types)
                if file_rule == default_rule:
                    rule_text = _format_rule_default_yaml(
                        file_rule, add_deprecated_rules=False)
                else:
                    # NOTE(gmann): If json file rule is not same as default
                    # means rule is overridden then do not comment out it in
                    # yaml file.
                    rule_text = _format_rule_default_yaml(
                        file_rule, comment_rule=False,
                        add_deprecated_rules=False)
                yaml_format_rules.append(rule_text)

    extra_rules_text = ("# WARNING: Below rules are either deprecated rules\n"
                        "# or extra rules in policy file, it is strongly\n"
                        "# recommended to switch to new rules.\n")
    # NOTE(gmann): If policy json file still using the deprecated rules which
    # will not be present in default rules list. Or it can be case of any
    # extra rule (old rule which is now removed) present in json file.
    # so let's keep these as it is (not commented out) to avoid breaking
    # existing deployment.
    if file_policies:
        yaml_format_rules.append(extra_rules_text)
    for file_rule, check_str in file_policies.items():
        rule_text = ('"%(name)s": "%(check_str)s"\n' %
                     {'name': file_rule,
                      'check_str': check_str})
        yaml_format_rules.append(rule_text)
    if conf.output_file:
        output_file = open(conf.output_file, 'w')
        output_file.writelines(yaml_format_rules)
        output_file.close()
    else:
        sys.stdout.writelines(yaml_format_rules)
