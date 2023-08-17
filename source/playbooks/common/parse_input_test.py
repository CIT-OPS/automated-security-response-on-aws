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
            print(parse_id_pattern,identifier_raw)
            identifier_match = re.match(
                parse_id_pattern,
                identifier_raw
            )
            print("identifier match",identifier_match)

            if identifier_match:
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
  "SchemaVersion": "2018-10-08",
  "Id": "arn:aws:securityhub:us-east-1:802214760415:subscription/aws-foundational-security-best-practices/v/1.0.0/DynamoDB.2/finding/9851b39f-3c7a-43a5-b59b-95000595e1ce",
  "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
  "ProductName": "Security Hub",
  "CompanyName": "AWS",
  "Region": "us-east-1",
  "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/DynamoDB.2",
  "AwsAccountId": "802214760415",
  "Types": [
    "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices"
  ],
  "FirstObservedAt": "2023-08-01T11:59:02.739Z",
  "LastObservedAt": "2023-08-01T11:59:14.661Z",
  "CreatedAt": "2023-08-01T11:59:02.739Z",
  "UpdatedAt": "2023-08-01T11:59:02.739Z",
  "Severity": {
    "Product": 40,
    "Label": "MEDIUM",
    "Normalized": 40,
    "Original": "MEDIUM"
  },
  "Title": "DynamoDB.2 DynamoDB tables should have point-in-time recovery enabled",
  "Description": "This control checks whether point-in-time recovery (PITR) is enabled for a DynamoDB table.",
  "Remediation": {
    "Recommendation": {
      "Text": "For information on how to correct this issue, consult the AWS Security Hub controls documentation.",
      "Url": "https://docs.aws.amazon.com/console/securityhub/DynamoDB.2/remediation"
    }
  },
  "ProductFields": {
    "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
    "StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:802214760415:subscription/aws-foundational-security-best-practices/v/1.0.0",
    "ControlId": "DynamoDB.2",
    "RecommendationUrl": "https://docs.aws.amazon.com/console/securityhub/DynamoDB.2/remediation",
    "RelatedAWSResources:0/name": "securityhub-dynamodb-pitr-enabled-47ef5d7d",
    "RelatedAWSResources:0/type": "AWS::Config::ConfigRule",
    "StandardsControlArn": "arn:aws:securityhub:us-east-1:802214760415:control/aws-foundational-security-best-practices/v/1.0.0/DynamoDB.2",
    "aws/securityhub/ProductName": "Security Hub",
    "aws/securityhub/CompanyName": "AWS",
    "Resources:0/Id": "arn:aws:dynamodb:us-east-1:802214760415:table/test-sharr-no-pitr-2",
    "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1::product/aws/securityhub/arn:aws:securityhub:us-east-1:802214760415:subscription/aws-foundational-security-best-practices/v/1.0.0/DynamoDB.2/finding/9851b39f-3c7a-43a5-b59b-95000595e1ce"
  },
  "UserDefinedFields": {
    "Platform": "",
    "securityContact": " Security Contact Details: Name:James R Daley | Title:Associate Director AWS Architecture | Email:jim.daley@concentrix.com | Phone +1 469-964-8040",
    "Dept": "Hosted",
    "OU": "testOU",
    "Enriched": "True",
    "Client": "Architecture Lab",
    "Name": "Architecture Lab",
    "jira": "kenneth.papagno@concentrix.com",
    "AccountName": "Lab-Architecture"
  },
  "Resources": [
    {
      "Type": "AwsDynamoDbTable",
      "Id": "arn:aws:dynamodb:us-east-1:802214760415:table/test-sharr-no-pitr-2",
      "Partition": "aws",
      "Region": "us-east-1"
    }
  ],
  "Compliance": {
    "Status": "FAILED",
    "SecurityControlId": "DynamoDB.2",
    "AssociatedStandards": [
      {
        "StandardsId": "standards/aws-foundational-security-best-practices/v/1.0.0"
      }
    ]
  },
  "WorkflowState": "NEW",
  "Workflow": {
    "Status": "NEW"
  },
  "RecordState": "ACTIVE",
  "Note": {
    "Text": "Account Name: Lab-Architecture OU Name: testOU Tags: Platform=, Client=Architecture Lab, Dept=Hosted, Name=Architecture Lab, jira=kenneth.papagno@concentrix.com Security Contact Details: Name:James R Daley | Title:Associate Director AWS Architecture | Email:jim.daley@concentrix.com | Phone +1 469-964-8040",
    "UpdatedBy": "Security Hub - Enrichment Automation",
    "UpdatedAt": "2023-08-01T11:59:23.101Z"
  },
  "FindingProviderFields": {
    "Severity": {
      "Label": "MEDIUM",
      "Original": "MEDIUM"
    },
    "Types": [
      "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices"
    ]
  },
  "ProcessedAt": "2023-08-01T11:59:23.136Z"
}

    event = {}
    event['Finding'] = finding
    #event['parse_id_pattern'] = '^arn:(?:aws|aws-us-gov|aws-cn):dynamodb:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:.*'
    event['parse_id_pattern'] = ''
    event['expected_control_id'] = 'DynamoDB.2'
    parse_event(event, None)
    
if __name__ == "__main__":
    main()