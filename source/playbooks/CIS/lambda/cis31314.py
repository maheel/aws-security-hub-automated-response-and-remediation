#!/usr/bin/python
###############################################################################
#  Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/                                        #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################

import os
import time
import boto3
import uuid
from botocore.config import Config
from lib.sechub_findings import Finding, notify
from lib.logger import Logger
from lib.awsapi_helpers import AWSClient, BotoSession
from lib.applogger import LogHandler
from lib.metrics import Metrics
from lib.ci3x_common import common_function

# ------------------------------
# Remediation-Specific
# ------------------------------
LAMBDA_ROLE = 'SO0111_CIS31314_memberRole'
REMEDIATION = 'Create a log metric filter and alarm for unauthorized API calls'
AFFECTED_OBJECT = 'CloudTrail'
# ------------------------------

PLAYBOOK = os.path.basename(__file__[:-3])
# initialise LOGGERs
LOG_LEVEL = os.getenv('log_level', 'info')
LOGGER = Logger(loglevel=LOG_LEVEL)
APPLOGGER = LogHandler(PLAYBOOK)  # application LOGGER for CW Logs

# Get AWS region from Lambda environment. If not present then we're not
# running under lambda, so defaulting to us-east-1
AWS_REGION = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
AWS_PARTITION = os.getenv('AWS_PARTITION', 'aws')

# Append region name to LAMBDA_ROLE
LAMBDA_ROLE += '_' + AWS_REGION
BOTO_CONFIG = Config(
    retries={
        'max_attempts': 10
    },
    region_name=AWS_REGION
)
AWS = AWSClient(AWS_PARTITION, AWS_REGION)


# ------------------------------------------------------------------------------
# HANDLER
# ------------------------------------------------------------------------------
def lambda_handler(event, context):
    LOGGER.debug(event)
    metrics = Metrics(event)
    try:
        for finding_rec in event['detail']['findings']:
            finding = Finding(finding_rec)
            LOGGER.info('FINDING_ID: ' + str(finding.details.get('Id')))
            remediate(finding, metrics.get_metrics_from_finding(finding_rec))
    except Exception as e:
        LOGGER.error(e)

    APPLOGGER.flush()  # flush the buffer to CW Logs


# ------------------------------------------------------------------------------
# REMEDIATION
# ------------------------------------------------------------------------------
def remediate(finding, metrics_data):
    message = {
        'Note': '',
        'State': 'INFO',
        'Account': finding.account_id,
        'AffectedObject': AFFECTED_OBJECT,
        'Remediation': REMEDIATION,
        'metrics_data': metrics_data
    }

    def failed():
        """
        Send Failed status message
        """
        message['State'] = 'FAILED'
        message['Note'] = ''
        notify(finding, message, LOGGER, cwlogs=APPLOGGER)

    # Make sure it matches - custom action can be initiated for any finding.
    # Ignore if the finding selected and the playbook do not match
    cis_data = finding.is_cis_ruleset()
    if not cis_data:
        # Not an applicable finding - does not match ruleset
        # send an error and exit
        LOGGER.debug('CIS 3.1 - 3.14: incorrect custom action selection.')
        APPLOGGER.add_message('CIS 3.1 - 3.14: incorrect custom action selection.')
        return

    if (cis_data['ruleid'] not in ['3.1', '3.2', '3.3', '3.4', '3.5', '3.6', '3.7', '3.8', '3.9', '3.10', '3.11', '3.12', '3.13', '3.14']):
        # Not an applicable finding - does not match rule
        # send an error and exit
        LOGGER.debug('CIS 3.1 - 3.14: incorrect custom action selection.')
        APPLOGGER.add_message('CIS 3.1 - 3.14: incorrect custom action selection.')
        return

    try:
        sess = BotoSession(finding.account_id, LAMBDA_ROLE)
        sns = sess.client('sns')
        logs = sess.client('logs')
        cloudwatch = sess.client('cloudwatch')
        cloudtrail = sess.client('cloudtrail')

    except Exception as e:
        LOGGER.error(e)
        return

    # Mark the finding NOTIFIED while we remediate
    message['State'] = 'INITIAL'
    notify(finding, message, LOGGER, cwlogs=APPLOGGER)
    try:
        print(cis_data['ruleid'])
        cloud_trails = cloudtrail.list_trails()

        cloudtrail_log_group = ''
        multi_region_trail = ''

        for cloud_trail in cloud_trails['Trails']:
            trail = cloudtrail.get_trail(
                Name=cloud_trail['Name']
            )

            trail_data = trail['Trail']

            if trail_data['IsMultiRegionTrail']:
                multi_region_trail = cloud_trail
                break

        if multi_region_trail and 'CloudWatchLogsLogGroupArn' in multi_region_trail:
            cloudtrail_log_group = multi_region_trail['CloudWatchLogsLogGroupArn'].split(':')[6]
        else:
            raise ValueError('Multi-region Cloudtrail should be configured before creating the alarm.')

    except Exception as e:
        LOGGER.error(e)
        message['State'] = 'FAILED'
        message['Note'] = 'Multi-region Cloudtrail should be configured with CloudWatch logs before creating the alarm.'
        notify(finding, message, LOGGER, cwlogs=APPLOGGER)
        return

    try:
        rule_id = cis_data['ruleid']

        metric_name = ''
        filter_name = ''
        alarm_name = ''
        alarm_description = ''
        filter_pattern = ''

        if rule_id == '3.1':
            metric_name = 'cis-unauthorised-api-calls-csi-31'
            filter_name = 'cis-unauthorized-api-calls-filter-cis-31'
            filter_pattern = '{($.errorCode="*UnauthorizedOperation") || ($.errorCode="AccessDenied*")}'
            alarm_name = 'CIS-3.1-UnauthorizedAPICalls'
            alarm_description = 'CIS-3.1 unauthorized API calls alarm'
        elif rule_id == '3.2':
            metric_name = 'console-sign-in-without-mfa-cis-32'
            filter_name = 'console-sign-in-without-mfa-cis-32'
            filter_pattern = '{($.eventName="ConsoleLogin") && ($.additionalEventData.MFAUsed !="Yes")}'
            alarm_name = 'CIS-3.2-ConsoleSigninWithoutMFA'
            alarm_description = 'CIS-3.2 Console Signin Without MFA'
        elif rule_id == '3.3':
            metric_name = 'root-account-usage-cis-33'
            filter_name = 'root-account-usage-cis-33'
            filter_pattern = '{$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"}'
            alarm_name = 'CIS-3.3-RootAccountUsage'
            alarm_description = 'CIS-3.3 Root Account Usage'
        elif rule_id == '3.4':
            metric_name = 'iam-policy-changes-cis-34'
            filter_name = 'iam-policy-changes-cis-34'
            filter_pattern = '{($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) ' \
                             '|| ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) ' \
                             '|| ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) ' \
                             '|| ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) ' \
                             '|| ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) ' \
                             '|| ($.eventName=DetachGroupPolicy)}'
            alarm_name = 'CIS-3.4-IAMPolicyChanges'
            alarm_description = 'CIS-3.4-IAMPolicyChanges'
        elif rule_id == '3.5':
            metric_name = 'cloudtrail-config-changes-cis-35'
            filter_name = 'cloudtrail-config-changes-cis-35'
            filter_pattern = '{($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) ' \
                             '|| ($.eventName=StartLogging) || ($.eventName=StopLogging)}'
            alarm_name = 'CIS-3.5-CloudTrailChanges'
            alarm_description = 'CIS-3.5 CloudTrail Changes'
        elif rule_id == '3.6':
            metric_name = 'console-authentication-failures-cis-36'
            filter_name = 'console-authentication-failures-cis-36'
            filter_pattern = '{($.eventName=ConsoleLogin) && ($.errorMessage="Failed authentication")}'
            alarm_name = 'CIS-3.6-ConsoleAuthenticationFailure'
            alarm_description = 'CIS-3.6 Console Authentication Failure'
        elif rule_id == '3.7':
            metric_name = 'disable-delete-customer-cmk-cis-37'
            filter_name = 'disable-delete-customer-cmk-cis-37'
            filter_pattern = '{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}'
            alarm_name = 'CIS-3.7-DisableOrDeleteCMK'
            alarm_description = 'CIS-3.7 Disable Or Delete CMK'
        elif rule_id == '3.8':
            metric_name = 's3-bucket-policy-changes-cis-38'
            filter_name = 's3-bucket-policy-changes-cis-38'
            filter_pattern = '{($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) ' \
                             '|| ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) ' \
                             '|| ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) ' \
                             '|| ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}'
            alarm_name = 'CIS-3.8-S3BucketPolicyChanges.'
            alarm_description = 'CIS-3.8 S3 Bucket Policy Changes.'
        elif rule_id == '3.9':
            metric_name = 'config-configuration-changes-cis-39'
            filter_name = 'config-configuration-changes-cis-39'
            filter_pattern = '{($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) ' \
                             '|| ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) ' \
                             '|| ($.eventName=PutConfigurationRecorder))}'
            alarm_name = 'CIS-3.9-AWSConfigChanges'
            alarm_description = 'CIS-3.9 AWS Config Changes'
        elif rule_id == '3.10':
            metric_name = 'security-group-changes-cis-310'
            filter_name = 'security-group-changes-cis-310'
            filter_pattern = '{($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) ' \
                             '|| ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) ' \
                             '|| ($.eventName=CreateSecurityGroup) || ($.eventName=DeleteSecurityGroup)}'
            alarm_name = 'CIS-3.10-SecurityGroupChanges'
            alarm_description = 'CIS-3.10 Security Group Changes'
        elif rule_id == '3.11':
            metric_name = 'nacl-changes-cis-311'
            filter_name = 'nacl-changes-cis-311'
            filter_pattern = '{($.eventName=CreateNetworkAcl) || ($.eventName=CreateNetworkAclEntry) || ' \
                             '($.eventName=DeleteNetworkAcl) || ($.eventName=DeleteNetworkAclEntry) || ' \
                             '($.eventName=ReplaceNetworkAclEntry) || ($.eventName=ReplaceNetworkAclAssociation)}'
            alarm_name = 'CIS-3.11-NetworkACLChanges'
            alarm_description = 'CIS-3.11 Network ACL Changes.'
        elif rule_id == '3.12':
            metric_name = 'network-gateway-changes-cis-312'
            filter_name = 'network-gateway-changes-cis-312'
            filter_pattern = '{($.eventName=CreateCustomerGateway) || ($.eventName=DeleteCustomerGateway) || ' \
                             '($.eventName=AttachInternetGateway) || ($.eventName=CreateInternetGateway) || ' \
                             '($.eventName=DeleteInternetGateway) || ($.eventName=DetachInternetGateway)}'
            alarm_name = 'CIS-3.12-NetworkGatewayChanges'
            alarm_description = 'CIS-3.12 Network Gateway Changes'
        if rule_id == '3.13':
            metric_name = 'route-table-changes-cis-313'
            filter_name = 'route-table-changes-cis-313'
            filter_pattern = '{($.eventName=CreateRoute) || ($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) ' \
                             '|| ($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) |' \
                             '| ($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable)}'
            alarm_name = 'CIS-3.13-RouteTableChanges'
            alarm_description = 'CIS-3.13 RouteTable Changes'
        if rule_id == '3.14':
            metric_name = 'vpc-changes-cis-314'
            filter_name = 'vpc-changes-cis-314'
            filter_pattern = '{($.eventName=CreateVpc) || ($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) ||' \
                             ' ($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) ||' \
                             ' ($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) ||' \
                             ' ($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || ' \
                             '($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)}'
            alarm_name = 'CIS-3.14-VPCChanges'
            alarm_description = 'CIS-3.14 VPC Changes'

        lowercase_str = uuid.uuid4().hex

        sns_topic_response = sns.create_topic(
            Name=f'cis-3-auto-remediate-alarms-{lowercase_str[0:10]}'
        )

        topic_arn = sns_topic_response['TopicArn']

        sns.subscribe(
            TopicArn=topic_arn,
            Protocol='email',
            Endpoint='test@test.com'
        )

        logs.put_metric_filter(
            logGroupName=cloudtrail_log_group,
            filterName=filter_name,
            filterPattern=filter_pattern,
            metricTransformations=[
                {
                    'metricName': metric_name,
                    'metricNamespace': 'LogMetrics',
                    'metricValue': '1',
                },
            ]
        )

        cloudwatch.put_metric_alarm(
            AlarmName=alarm_name,
            AlarmDescription=alarm_description,
            ActionsEnabled=True,
            AlarmActions=[topic_arn],
            MetricName=metric_name,
            Namespace='LogMetrics',
            Statistic='Average',
            EvaluationPeriods=1,
            Period=300,
            Threshold=1,
            ComparisonOperator='GreaterThanOrEqualToThreshold',
        )

        # Mark the finding NOTIFIED while we remediate
        message['State'] = 'INITIAL'
        notify(finding, message, LOGGER, cwlogs=APPLOGGER)

    except Exception as e:
        LOGGER.error(e)
        failed()
        return
