# Copyright CNXC. All Rights Reserved.

import json
from botocore.config import Config
import boto3

responses = {}
responses["AssociateWAFResponse"] = []

def connect_to_wafv2(boto_config):
    return boto3.client("wafv2", config=boto_config)

def get_account(boto_config):
    return boto3.client('sts', config=boto_config).get_caller_identity()['Account']

def associate_wafv2_with_apigateway(ResourceId, web_acl_arn):
    # Initialize the WAFv2 client
    ResourceRegion = ResourceId.split(":")[3]
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name = ResourceRegion)
    wafv2_client = connect_to_wafv2(BOTO_CONFIG)

    # Associate the WebACL with the API Gateway stage
    waf_association_response = wafv2_client.associate_web_acl(
        ResourceArn=ResourceId,
        WebACLArn=web_acl_arn
    )

    print(f"WebACL {web_acl_arn} associated with API Gateway {ResourceId}")
    return waf_association_response

def runbook_handler(event, context):
    # Replace these values with your actual API Gateway ID, stage name, and WAFv2 WebACL ARN
    ResourceId = event['ResourceId']
    waf_arn = event['WAF_ARN']
    print (f"Associating {ResourceId} with WAF {waf_arn}" )
    
    association_response = associate_wafv2_with_apigateway(ResourceId, waf_arn)
    responses["AssociateWAFResponse"] = association_response
    return {"output": "WAF Association successful.", "http_responses": responses}

if __name__ == "__main__":
    event = {
       "ResourceId": "arn:aws:apigateway:us-east-2::/restapis/o561sl29pj/stages/test",
       "WAF_Arn": "arn:aws:wafv2:us-east-2:234772128127:regional/webacl/SHARR-Default-WAF-Regional/a0d388f7-349d-40db-9453-12a5202c09e9"
    }
    result = runbook_handler(event,"")
    print(result)