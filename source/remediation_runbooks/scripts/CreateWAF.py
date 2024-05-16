# Copyright CNXC. All Rights Reserved.

import json
from botocore.config import Config
import boto3



responses = {}
responses["CreateWAFResponse"] = []

def connect_to_wafv2(boto_config):
    return boto3.client("wafv2", config=boto_config)

def get_account(boto_config):
    return boto3.client('sts', config=boto_config).get_caller_identity()['Account']

def runbook_handler(event, context):
    ResourceId = event['ResourceId']
    ResourceRegion = ResourceId.split(":")[3]
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name = ResourceRegion)

    account = get_account(BOTO_CONFIG)

    waf_name = "SHARR-Default-WAF-Regional"
    wafv2 = connect_to_wafv2(BOTO_CONFIG)
    wafARN = does_waf_exist(wafv2, waf_name)
    if wafARN == False:
        result = wafv2.create_web_acl(
            Name=waf_name,
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': 'SHARR_WAF_REGIONAL'
            },
            Tags=[
                {"Key": "Name", "Value": "AWSBP REGIONAL Default WAF"},
            ],
            Rules=[
            {   "Name": "AWS-AWSManagedRulesAmazonIpReputationList",
                "Priority": 0,
                "Statement": {
                    "ManagedRuleGroupStatement": {
                        "VendorName": "AWS",
                        "Name": "AWSManagedRulesAmazonIpReputationList"
                    }
                },
                "OverrideAction": {
                    "None": {}
                },
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "AWS-AWSManagedRulesAmazonIpReputationList"
                }
            },
            {
                "Name": "AWS-AWSManagedRulesCommonRuleSet",
                "Priority": 1,
                "Statement": {
                    "ManagedRuleGroupStatement": {
                        "VendorName": "AWS",
                        "Name": "AWSManagedRulesCommonRuleSet"
                    }
                },
                "OverrideAction": {
                    "None": {}
                },
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "AWS-AWSManagedRulesCommonRuleSet"
                }
            },
            {
                "Name": "AWS-AWSManagedRulesKnownBadInputsRuleSet",
                "Priority": 2,
                "Statement": {
                    "ManagedRuleGroupStatement": {
                        "VendorName": "AWS",
                        "Name": "AWSManagedRulesKnownBadInputsRuleSet"
                    }
                },
                "OverrideAction": {
                    "None": {}
                },
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "AWS-AWSManagedRulesKnownBadInputsRuleSet"
                }
            },
            {
                "Name": "AWS-AWSManagedRulesSQLiRuleSet",
                "Priority": 3,
                "Statement": {
                    "ManagedRuleGroupStatement": {
                        "VendorName": "AWS",
                        "Name": "AWSManagedRulesSQLiRuleSet"
                    }
                },
                "OverrideAction": {
                    "None": {}
                },
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "AWS-AWSManagedRulesSQLiRuleSet"
                }
            }
            ]
        )
        return {
            'message': 'WAF CREATED',
            'WAF_ARN': wafARN
        }

    else:
        return {
            'message': 'EXISTING WAF FOUND',
            'WAF_ARN': wafARN
        }


def does_waf_exist(wafv2, waf_name):
    waf_exists = False
    try:
        response = wafv2.list_web_acls(Scope="REGIONAL")
        for WebACL in response["WebACLs"]:
            if WebACL["Name"] == waf_name:
                waf_exists = WebACL["ARN"]
                break

    except wafv2.exceptions.WAFInternalErrorException:
        waf_exists = False

    return waf_exists


if __name__ == "__main__":
    event = {
       "ResourceId": "arn:aws:apigateway:us-east-2::/restapis/o561sl29pj/stages/test",
    }
    result = runbook_handler(event,"")
    print(result)
