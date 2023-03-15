import logging
import os

import boto3

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC")
EC2_CLIENT = boto3.client("ec2")
SNS_CLIENT = boto3.client("sns")

OPEN_IP_RANGE = "0.0.0.0/0"

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


def get_field_from_event_or_detail(event, field):
    return event.get(field, event.get("detail", {})[field])


def lambda_handler(event, context):
    LOGGER.info(f"EVENT: {event}")

    event_name = get_field_from_event_or_detail(event, "eventName")
    LOGGER.debug(f"EVENT NAME: {event_name}")
    if event_name == "AuthorizeSecurityGroupIngress":
        check_ingress_rule_changes(
            get_field_from_event_or_detail(event, "requestParameters")["groupId"],
            get_field_from_event_or_detail(event, "responseElements")[
                "securityGroupRuleSet"
            ]["items"],
        )
    elif event_name == "RunInstances":
        check_if_instance_has_illegal_security_group(
            get_field_from_event_or_detail(event, "responseElements")["instancesSet"][
                "items"
            ],
        )

    elif event_name == "ModifyNetworkInterfaceAttribute":
        request_parameters = get_field_from_event_or_detail(event, "requestParameters")
        interface_id = request_parameters.get("networkInterfaceId", None)
        groups = request_parameters.get("groupSet", None)

        if interface_id and groups:
            check_if_network_interface_got_illegal_sg(interface_id, groups["items"])
        else:
            LOGGER.info(f"Not an interesting change, so does nothing")
    else:
        raise f"Not supported event type {event_name}"

    result = "Verified change"
    return {"statusCode": 200, "body": result}


def check_if_network_interface_got_illegal_sg(interface_id, groups):
    LOGGER.info(f"Checks security groups added to the network interface {interface_id}")
    group_ids = [g["groupId"] for g in groups]
    verify_security_groups(group_ids)


def check_if_instance_has_illegal_security_group(instances):
    LOGGER.info(f"Checks security groups for ingress rules for started instances")
    for instance in instances:
        LOGGER.debug(instance)
        for network_interface in instance["networkInterfaceSet"]["items"]:
            group_ids = [g["groupId"] for g in network_interface["groupSet"]["items"]]
            verify_security_groups(group_ids, instance["instanceId"])


def verify_security_groups(group_ids, instance_id=None):

    for group_id in group_ids:
        LOGGER.debug(group_id)
        # TODO: should loop until nexttoken is None
        sg_rules = EC2_CLIENT.describe_security_group_rules(
            Filters=[{"Name": "group-id", "Values": [group_id]}]
        )
        LOGGER.info(sg_rules)

        check_ingress_rule_changes(
            group_id, sg_rules["SecurityGroupRules"], instance_id
        )


def check_ingress_rule_changes(group_id, rules, instance_id=None):
    LOGGER.info(f"Checks ingress rules for group: {group_id}")
    # Only remediate if security group is attached to  EC2 instance
    if instance_id is None:
        LOGGER.info("Instance id is not provided by the event")
        # TODO: for performance it would be best to do this only if group has an invalid rule
        instance_ids = get_instances_group_is_used_on(group_id)
        if len(instance_ids) == 0:
            LOGGER.info(f"Group {group_id} is not connected to any instances")
            return
        else:
            instance_id = ",".join(instance_ids)

    for rule in rules:
        LOGGER.info(rule)
        # is field names are different depending if we got it from the describe rules api method or event
        isegress_field_name = "isEgress" if "isEgress" in rule else "IsEgress"
        cidripv4_field_name = "cidrIpv4" if "cidrIpv4" in rule else "CidrIpv4"
        ruleid_field_name = (
            "securityGroupRuleId"
            if "securityGroupRuleId" in rule
            else "SecurityGroupRuleId"
        )

        if (
            not rule[
                isegress_field_name
            ]  # make sure the rule is for ingress not egress
            and rule.get(cidripv4_field_name, "") == OPEN_IP_RANGE
        ):
            rule_id = rule.get(ruleid_field_name, "")
            LOGGER.info(f"Rule {rule_id} allow illegal trafic for group: {group_id}")

            remove_rule_and_push_notification(group_id, rule_id, instance_id)


def get_instances_group_is_used_on(group_id):

    LOGGER.info(f"Finding usage of {group_id}")
    # TODO: should loop until next token is None
    interfaces = EC2_CLIENT.describe_network_interfaces(
        Filters=[{"Name": "group-id", "Values": [group_id]}]
    )
    instance_ids = []
    for interface in interfaces["NetworkInterfaces"]:
        attachment = interface.get("Attachment", {})
        if attachment.get("InstanceId", "").startswith("i-"):
            instance_ids.append(attachment.get("InstanceId", ""))
    return instance_ids


def remove_rule_and_push_notification(group_id, rule_id, instance_id):
    LOGGER.info(
        f"Removing rule and notifying {rule_id} for group {group_id} that is attached to instance {instance_id}"
    )
    delete_ingress_rule(group_id, rule_id)
    push_notification(
        f"Security group {group_id} has unsecure change",
        f"Security group {group_id} got added rule {rule_id} that allowed ingress from 0.0.0.0/0. This rule was automatic removed of security reasons. The group was attached to instance {instance_id}",
    )


def delete_ingress_rule(group_id, rule_id):
    LOGGER.info(f"Removing rule {rule_id} for group {group_id}")
    EC2_CLIENT.revoke_security_group_ingress(
        GroupId=group_id, SecurityGroupRuleIds=[rule_id]
    )


def push_notification(subject, message):
    SNS_CLIENT.publish(
        TopicArn=SNS_TOPIC_ARN,
        Message=message,
        Subject=subject,
    )
