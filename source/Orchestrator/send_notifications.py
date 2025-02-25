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

import json
from json.decoder import JSONDecodeError
import boto3
import os
from botocore.config import Config
import sechub_findings
from logger import Logger
from applogger import LogHandler
from metrics import Metrics

# Get AWS region from Lambda environment. If not present then we're not
# running under lambda, so defaulting to us-east-1
AWS_REGION = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')   # MUST BE SET in global variables
AWS_PARTITION = os.getenv('AWS_PARTITION', 'aws')           # MUST BE SET in global variables

# initialise loggers
LOG_LEVEL = os.getenv('log_level', 'info')
LOGGER = Logger(loglevel=LOG_LEVEL)

BOTO_CONFIG = Config(
    retries={
        'max_attempts': 10
    }
)
def format_details_for_output(details):
    """Handle various possible formats in the details"""
    details_formatted = []
    if isinstance(details, list):
        details_formatted = details
    elif isinstance(details, str) and details[0:6] == "Cause:":
        try:
            details_formatted = json.loads(details[7:]).split("\n")
        except JSONDecodeError:
            details_formatted.append(details[7:])
    elif isinstance(details, str):
        try:
            details_formatted = json.loads(details)
        except JSONDecodeError:
            details_formatted.append(details)
    else:
        details_formatted.append(details)

    return details_formatted

def lambda_handler(event, context):
    # Expected input:
    # Notification:
    #   Message: string
    #   State: string
    #   Details?: string
    #   updateSecHub: yes|NO
    # Payload: contains the Step Function Input to the previous state and consists of:
    #   Finding?: json
    #   ControlId?: string
    #   SecurityStandard?: string
    #   EventType?: string

    message_prefix = event['Notification'].get('ExecId','')
    if message_prefix:
        message_prefix += ': '
    message_suffix = event['Notification'].get('AffectedObject', '')
    if message_suffix:
        message_suffix = ': ' + message_suffix

    # Get finding status
    finding_status = 'FAILED' # default state
    if event['Notification']['State'] == 'SUCCESS':
        finding_status = 'RESOLVED'

    finding = None
    if 'Finding' in event:
        finding = sechub_findings.Finding(event['Finding'])

    # Send anonymous metrics
    if 'EventType' in event and 'Finding' in event:
        metrics = Metrics(event['Metrics'],event['EventType'])
        metrics_data = metrics.get_metrics_from_finding(event['Finding'])
        metrics_data['status'] = finding_status
        metrics.send_metrics(metrics_data)

    if event['Notification']['State'].upper() == 'SUCCESS':
        notification = sechub_findings.SHARRNotification(
            event.get('SecurityStandard', 'APP'),
            event.get('ControlId', None),
            'ORCHESTRATOR'
        )
        notification.severity = 'INFO'
        notification.send_to_sns = True

    elif event['Notification']['State'].upper() == 'WRONGSTANDARD':
        notification = sechub_findings.SHARRNotification('APP', None, 'ORCHESTRATOR')
        notification.severity = 'ERROR'

    else:
        notification = sechub_findings.SHARRNotification(
            event.get('SecurityStandard', 'APP'),
            event.get('ControlId', None),
            'ORCHESTRATOR'
        )
        notification.severity = 'ERROR'
        if finding:
            finding.flag(event['Notification']['Message'])

    notification.message = message_prefix + event['Notification']['Message'] + message_suffix
    if 'Details' in event['Notification'] and event['Notification']['Details'] != 'MISSING':
        notification.logdata = format_details_for_output(event['Notification']['Details'])
    notification.notify()
