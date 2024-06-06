# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
from botocore.config import Config

responses = {}
responses["CreateWAFResponse"] = []


def connect_to_wafv2(boto_config):
    return boto3.client("wafv2", config=boto_config)


def runbook_handler(event, context):
    ResourceId = event["ResourceId"]
    ResourceType = event["ResourceType"]
    ResourceRegion = ResourceId.split(":")[3]
    if ResourceRegion == "":
        ResourceRegion = "us-east-1"
    # print(f"ResourceRegion: {ResourceRegion}")

    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=ResourceRegion)

    if ResourceType == "AwsCloudFrontDistribution":
        # print("CloudFront Distribution")
        waf_name = "ASR-Default-WAF-CloudFront"
        wafv2 = connect_to_wafv2(BOTO_CONFIG)
        wafARN = does_waf_exist(wafv2, waf_name, ResourceType)
        if wafARN is False:
            # print("CloudFront Distribution WAF DOES NOT EXIST")
            response = wafv2.create_web_acl(
                Name=waf_name,
                Scope="CLOUDFRONT",
                DefaultAction={"Allow": {}},
                VisibilityConfig={
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "ASR_WAF_CLOUDFRONT",
                },
                Tags=[
                    {"Key": "Name", "Value": "ASR CLOUDFRONT Default WAF"},
                ],
                Rules=[
                    {
                        "Name": "AWS-AWSManagedRulesAmazonIpReputationList",
                        "Priority": 0,
                        "Statement": {
                            "ManagedRuleGroupStatement": {
                                "VendorName": "AWS",
                                "Name": "AWSManagedRulesAmazonIpReputationList",
                            }
                        },
                        "OverrideAction": {"None": {}},
                        "VisibilityConfig": {
                            "SampledRequestsEnabled": True,
                            "CloudWatchMetricsEnabled": True,
                            "MetricName": "AWS-AWSManagedRulesAmazonIpReputationList",
                        },
                    },
                    {
                        "Name": "AWS-AWSManagedRulesCommonRuleSet",
                        "Priority": 1,
                        "Statement": {
                            "ManagedRuleGroupStatement": {
                                "VendorName": "AWS",
                                "Name": "AWSManagedRulesCommonRuleSet",
                            }
                        },
                        "OverrideAction": {"None": {}},
                        "VisibilityConfig": {
                            "SampledRequestsEnabled": True,
                            "CloudWatchMetricsEnabled": True,
                            "MetricName": "AWS-AWSManagedRulesCommonRuleSet",
                        },
                    },
                    {
                        "Name": "AWS-AWSManagedRulesKnownBadInputsRuleSet",
                        "Priority": 2,
                        "Statement": {
                            "ManagedRuleGroupStatement": {
                                "VendorName": "AWS",
                                "Name": "AWSManagedRulesKnownBadInputsRuleSet",
                            }
                        },
                        "OverrideAction": {"None": {}},
                        "VisibilityConfig": {
                            "SampledRequestsEnabled": True,
                            "CloudWatchMetricsEnabled": True,
                            "MetricName": "AWS-AWSManagedRulesKnownBadInputsRuleSet",
                        },
                    },
                ],
            )
            wafARN = response["Summary"]["ARN"]
            # print(f"CloudFront WAF Created {wafARN}")
            return {"message": "CLOUDFRONT WAF CREATED", "WAF_ARN": wafARN}
        else:
            # print(f"CloudFront Distribution Already Exists {wafARN}")
            return {"message": "CLOUDFRONT WAF ALREADY EXISTS", "WAF_ARN": wafARN}
    else:
        waf_name = "ASR-Default-WAF-Regional"
        wafv2 = connect_to_wafv2(BOTO_CONFIG)
        wafARN = does_waf_exist(wafv2, waf_name, ResourceType)
        if wafARN is False:
            response = wafv2.create_web_acl(
                Name=waf_name,
                Scope="REGIONAL",
                DefaultAction={"Allow": {}},
                VisibilityConfig={
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "ASR_WAF_REGIONAL",
                },
                Tags=[
                    {"Key": "Name", "Value": "AWSBP REGIONAL Default WAF"},
                ],
                Rules=[
                    {
                        "Name": "AWS-AWSManagedRulesAmazonIpReputationList",
                        "Priority": 0,
                        "Statement": {
                            "ManagedRuleGroupStatement": {
                                "VendorName": "AWS",
                                "Name": "AWSManagedRulesAmazonIpReputationList",
                            }
                        },
                        "OverrideAction": {"None": {}},
                        "VisibilityConfig": {
                            "SampledRequestsEnabled": True,
                            "CloudWatchMetricsEnabled": True,
                            "MetricName": "AWS-AWSManagedRulesAmazonIpReputationList",
                        },
                    },
                    {
                        "Name": "AWS-AWSManagedRulesCommonRuleSet",
                        "Priority": 1,
                        "Statement": {
                            "ManagedRuleGroupStatement": {
                                "VendorName": "AWS",
                                "Name": "AWSManagedRulesCommonRuleSet",
                            }
                        },
                        "OverrideAction": {"None": {}},
                        "VisibilityConfig": {
                            "SampledRequestsEnabled": True,
                            "CloudWatchMetricsEnabled": True,
                            "MetricName": "AWS-AWSManagedRulesCommonRuleSet",
                        },
                    },
                    {
                        "Name": "AWS-AWSManagedRulesKnownBadInputsRuleSet",
                        "Priority": 2,
                        "Statement": {
                            "ManagedRuleGroupStatement": {
                                "VendorName": "AWS",
                                "Name": "AWSManagedRulesKnownBadInputsRuleSet",
                            }
                        },
                        "OverrideAction": {"None": {}},
                        "VisibilityConfig": {
                            "SampledRequestsEnabled": True,
                            "CloudWatchMetricsEnabled": True,
                            "MetricName": "AWS-AWSManagedRulesKnownBadInputsRuleSet",
                        },
                    },
                    {
                        "Name": "AWS-AWSManagedRulesSQLiRuleSet",
                        "Priority": 3,
                        "Statement": {
                            "ManagedRuleGroupStatement": {
                                "VendorName": "AWS",
                                "Name": "AWSManagedRulesSQLiRuleSet",
                            }
                        },
                        "OverrideAction": {"None": {}},
                        "VisibilityConfig": {
                            "SampledRequestsEnabled": True,
                            "CloudWatchMetricsEnabled": True,
                            "MetricName": "AWS-AWSManagedRulesSQLiRuleSet",
                        },
                    },
                ],
            )
            wafARN = response["Summary"]["ARN"]
            return {"message": "REGIONAL WAF CREATED", "WAF_ARN": wafARN}
        else:
            return {"message": "EXISTING REGIONAL WAF FOUND", "WAF_ARN": wafARN}


def does_waf_exist(wafv2, waf_name, ResourceType):
    waf_exists = False
    if ResourceType != "AwsCloudFrontDistribution":
        try:
            response = wafv2.list_web_acls(Scope="REGIONAL")
            for WebACL in response["WebACLs"]:
                if WebACL["Name"] == waf_name:
                    waf_exists = WebACL["ARN"]
                    break

        except wafv2.exceptions.WAFInternalErrorException:
            waf_exists = False
    else:
        try:
            response = wafv2.list_web_acls(Scope="CLOUDFRONT")
            for WebACL in response["WebACLs"]:
                if WebACL["Name"] == waf_name:
                    waf_exists = WebACL["ARN"]
                    break

        except wafv2.exceptions.WAFInternalErrorException:
            waf_exists = False

    return waf_exists


if __name__ == "__main__":
    event = {
        "AccountId": "211125410042",
        "ResourceId": "arn:aws:apigateway:us-east-1::/restapis/t2wlyuj26b/stages/PROD",
        "Region": "us-east-1",
        "ResourceType": "AwsApiGatewayStage",
    }
    result = runbook_handler(event, "")
    print(result)
