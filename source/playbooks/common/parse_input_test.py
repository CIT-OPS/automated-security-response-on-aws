# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import re
import json
import boto3
from botocore.config import Config

def connect_to_config(boto_config):
    return boto3.client('config', config=boto_config)

def connect_to_ssm(boto_config):
    return boto3.client('ssm', config=boto_config)

def get_solution_id():
    return 'SO0111'

def get_solution_version():
    ssm = connect_to_ssm(
        Config(
            retries = {
                'mode': 'standard'
            },
            user_agent_extra = f'AwsSolution/{get_solution_id()}/unknown'
        )
    )
    solution_version = 'unknown'
    try:
        ssm_parm_value = ssm.get_parameter(
            Name=f'/Solutions/{get_solution_id()}/member-version'
        )['Parameter'].get('Value', 'unknown')
        solution_version = ssm_parm_value
    except Exception as e:
        print(e)
        print(f'ERROR getting solution version')
    return solution_version

def get_shortname(long_name):
    short_name = {
        'aws-foundational-security-best-practices': 'AFSBP',
        'cis-aws-foundations-benchmark': 'CIS',
        'pci-dss': 'PCI',
        'security-control': 'SC'
    }
    return short_name.get(long_name, None)

def get_config_rule(rule_name):
    boto_config = Config(
        retries = {
            'mode': 'standard'
        },
        user_agent_extra = f'AwsSolution/{get_solution_id()}/{get_solution_version()}'
    )
    config_rule = None
    try:
        configsvc = connect_to_config(boto_config)
        config_rule = configsvc.describe_config_rules(
            ConfigRuleNames=[ rule_name ]
        ).get('ConfigRules', [])[0]
    except Exception as e:
        print(e)
        exit(f'ERROR getting config rule {rule_name}')
    return config_rule

class FindingEvent:
    """
    Finding object returns the parse fields from an input finding json object
    """
    def _get_resource_id(self, parse_id_pattern, resource_index):
        identifier_raw = self.finding_json['Resources'][0]['Id']
        self.resource_id = identifier_raw
        self.resource_id_matches = []

        if parse_id_pattern:
            print(f"parse_id_pattern {parse_id_pattern} identifier_raw {identifier_raw}")
            identifier_match = re.match(
                parse_id_pattern,
                identifier_raw
            )
            
            if identifier_match:
                print("groups",identifier_match.groups())
                for group in range(1, len(identifier_match.groups())+1):
                    self.resource_id_matches.append(identifier_match.group(group))
                self.resource_id = identifier_match.group(resource_index)
            else:
                exit(f'ERROR: Invalid resource Id {identifier_raw}')
    
    def _get_sc_check(self):
        match_finding_id = re.match(
            r'^arn:(?:aws|aws-cn|aws-us-gov):securityhub:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:'+
            'security-control/(.*)/finding/(?i:[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})$',
            self.finding_json['Id']
        )
        if match_finding_id:
            self.standard_id = get_shortname('security-control')
            self.control_id = match_finding_id.group(1)

        return match_finding_id

    def _get_standard_info(self):
        match_finding_id = re.match(
            r'^arn:(?:aws|aws-cn|aws-us-gov):securityhub:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:'+
            'subscription/(.*?)/v/(\d+\.\d+\.\d+)/(.*)/finding/(?i:[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})$',
            self.finding_json['Id']
        )
        if match_finding_id:
            self.standard_id = get_shortname(match_finding_id.group(1))
            self.standard_version = match_finding_id.group(2)
            self.control_id = match_finding_id.group(3)
        else:
            match_sc_finding_id = self._get_sc_check()
            if not match_sc_finding_id:
                self.valid_finding = False
                self.invalid_finding_reason = f'Finding Id is invalid: {self.finding_json["Id"]}'

    def _get_aws_config_rule(self):
        # config_rule_id refers to the AWS Config Rule that produced the finding
        if "RelatedAWSResources:0/type" in self.finding_json['ProductFields'] and self.finding_json['ProductFields']['RelatedAWSResources:0/type'] == 'AWS::Config::ConfigRule':
            self.aws_config_rule_id = self.finding_json['ProductFields']['RelatedAWSResources:0/name']
            self.aws_config_rule = get_config_rule(self.aws_config_rule_id)

    def _get_region_from_resource_id(self):
        check_for_region = re.match(
            r'^arn:(?:aws|aws-cn|aws-us-gov):[a-zA-Z0-9]+:([a-z]{2}(?:-gov)?-[a-z]+-\d):.*:.*$',
            self.finding_json['Resources'][0]['Id']
        )
        if check_for_region:
            self.resource_region = check_for_region.group(1)

    def __init__(self, finding_json, parse_id_pattern, expected_control_id, resource_index):
        self.valid_finding = True
        self.resource_region = None
        self.control_id = None
        self.aws_config_rule_id = None
        self.aws_config_rule = {}

        """Populate fields"""
        # v1.5
        self.finding_json = finding_json
        self._get_resource_id(parse_id_pattern, resource_index)     # self.resource_id, self.resource_id_matches
        self._get_standard_info()                                   # self.standard_id, self.standard_version, self.control_id

        # V1.4
        self.account_id = self.finding_json.get('AwsAccountId', None)    # deprecate - get Finding.AwsAccountId
        if not re.match(r'^\d{12}$', self.account_id) and self.valid_finding:
            self.valid_finding = False
            self.invalid_finding_reason = f'AwsAccountId is invalid: {self.account_id}'
        self.finding_id = self.finding_json.get('Id', None)              # deprecate
        self.product_arn = self.finding_json.get('ProductArn', None)
        if not re.match(r'^arn:(?:aws|aws-cn|aws-us-gov):securityhub:[a-z]{2}(?:-gov)?-[a-z]+-\d::product/aws/securityhub$', self.product_arn):
            if self.valid_finding:
                self.valid_finding = False
                self.invalid_finding_reason = f'ProductArn is invalid: {self.product_arn}'
        self.details = self.finding_json['Resources'][0].get('Details', {})
        # Test mode is used with fabricated finding data to tell the
        # remediation runbook to run in test more (where supported)
        # Currently not widely-used and perhaps should be deprecated.
        self.testmode = bool('testmode' in self.finding_json)
        self.resource = self.finding_json['Resources'][0]
        self._get_region_from_resource_id()
        self._get_aws_config_rule()
        self.affected_object = {'Type': self.resource['Type'], 'Id': self.resource_id, 'OutputKey': 'Remediation.Output'}

        # Validate control_id
        if not self.control_id:
            if self.valid_finding:
                self.valid_finding = False
                self.invalid_finding_reason = f'Finding Id is invalid: {self.finding_json["Id"]} - missing Control Id'
        elif self.control_id not in expected_control_id:  # ControlId is the expected value
            if self.valid_finding:
                self.valid_finding = False
                self.invalid_finding_reason = f'Control Id from input ({self.control_id}) does not match {str(expected_control_id)}'

        if not self.resource_id and self.valid_finding:
            self.valid_finding = False
            self.invalid_finding_reason = 'Resource Id is missing from the finding json Resources (Id)'

        if not self.valid_finding:
            # Error message and return error data
            msg = f'ERROR: {self.invalid_finding_reason}'
            exit(msg)

    def __str__(self):
        return json.dumps(self.__dict__)

'''
MAIN
'''
def parse_event(event, _):
    finding_event = FindingEvent(event['Finding'], event['parse_id_pattern'], event['expected_control_id'], event.get('resource_index', 1))

    if not finding_event.valid_finding:
        exit('ERROR: Finding is not valid')

    return {
        "account_id": finding_event.account_id,
        "resource_id": finding_event.resource_id,
        "finding_id": finding_event.finding_id,         # Deprecate v1.5.0+
        "control_id": finding_event.control_id,
        "product_arn": finding_event.product_arn,       # Deprecate v1.5.0+
        "object": finding_event.affected_object,
        "matches": finding_event.resource_id_matches,
        "details": finding_event.details,               # Deprecate v1.5.0+
        "testmode": finding_event.testmode,             # Deprecate v1.5.0+
        "resource": finding_event.resource,
        "resource_region": finding_event.resource_region,
        "finding": finding_event.finding_json,
        "aws_config_rule": finding_event.aws_config_rule
    }

def main():
    finding = {
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
    "Types": [
      "Software and Configuration Checks/Industry and Regulatory Standards"
    ],
    "Description": "This control checks whether point-in-time recovery (PITR) is enabled for a DynamoDB table.",
    "Compliance": {
      "Status": "FAILED",
      "SecurityControlId": "DynamoDB.2",
      "AssociatedStandards": [
        {
          "StandardsId": "standards/aws-foundational-security-best-practices/v/1.0.0"
        }
      ]
    },
    "ProductName": "Security Hub",
    "FirstObservedAt": "2023-09-05T23:42:00.140Z",
    "CreatedAt": "2023-09-05T23:42:00.140Z",
    "LastObservedAt": "2023-09-05T23:42:14.825Z",
    "CompanyName": "AWS",
    "FindingProviderFields": {
      "Types": [
        "Software and Configuration Checks/Industry and Regulatory Standards"
      ],
      "Severity": {
        "Normalized": 40,
        "Label": "MEDIUM",
        "Original": "MEDIUM"
      }
    },
    "ProductFields": {
      "RelatedAWSResources:0/name": "securityhub-dynamodb-pitr-enabled-ae09b360",
      "RelatedAWSResources:0/type": "AWS::Config::ConfigRule",
      "aws/securityhub/ProductName": "Security Hub",
      "aws/securityhub/CompanyName": "AWS",
      "Resources:0/Id": "arn:aws:dynamodb:us-east-1:332241576022:table/test_delete_me",
      "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1::product/aws/securityhub/arn:aws:securityhub:us-east-1:332241576022:security-control/DynamoDB.2/finding/a6a913d6-24db-4554-aa79-9c4fa457e6c8"
    },
    "Remediation": {
      "Recommendation": {
        "Text": "For information on how to correct this issue, consult the AWS Security Hub controls documentation.",
        "Url": "https://docs.aws.amazon.com/console/securityhub/DynamoDB.2/remediation"
      }
    },
    "SchemaVersion": "2018-10-08",
    "GeneratorId": "security-control/DynamoDB.2",
    "RecordState": "ACTIVE",
    "Title": "DynamoDB tables should have point-in-time recovery enabled",
    "Workflow": {
      "Status": "NEW"
    },
    "Severity": {
      "Normalized": 40,
      "Label": "MEDIUM",
      "Original": "MEDIUM"
    },
    "UpdatedAt": "2023-09-05T23:42:00.140Z",
    "WorkflowState": "NEW",
    "AwsAccountId": "332241576022",
    "Region": "us-east-1",
    "Id": "arn:aws:securityhub:us-east-1:332241576022:security-control/DynamoDB.2/finding/a6a913d6-24db-4554-aa79-9c4fa457e6c8",
    "Resources": [
      {
        "Partition": "aws",
        "Type": "AwsDynamoDbTable",
        "Region": "us-east-1",
        "Id": "arn:aws:dynamodb:us-east-1:332241576022:table/test_delete_me"
      }
    ],
    "Note": {
      "UpdatedBy": "Security Hub - Enrichment Automation",
      "Text": "Account Name: SecurityHub-Admin OU Name: citCore Tags: Platform=Core Services, Client=SharedAllocation_All, Dept=SharedAllocation, Name=SecurityHub-Admin Security Contact Details: Name:James R Daley | Title:Associate Director AWS Architecture | Email:jim.daley@concentrix.com | Phone +1 469-964-8040",
      "UpdatedAt": "2023-09-05T23:42:28.546Z"
    },
    "UserDefinedFields": {
      "Platform": "Core Services",
      "securityContact": " Security Contact Details: Name:James R Daley | Title:Associate Director AWS Architecture | Email:jim.daley@concentrix.com | Phone +1 469-964-8040",
      "Dept": "SharedAllocation",
      "OU": "citCore",
      "Enriched": "True",
      "Client": "SharedAllocation_All",
      "Name": "SecurityHub-Admin",
      "AccountName": "SecurityHub-Admin"
    },
    "ProcessedAt": "2023-09-05T23:42:28.561Z"
  }
    event = {}
    event['Finding'] = finding
    #event['parse_id_pattern'] = '^arn:(?:aws|aws-us-gov|aws-cn):dynamodb:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:.*'
    event['parse_id_pattern'] = '^arn:(?:aws|aws-us-gov|aws-cn):dynamodb:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:table/(.*)$'
    event['expected_control_id'] = 'DynamoDB.2'
    x =parse_event(event, None)
    print(x)
    
if __name__ == "__main__":
    main()
    