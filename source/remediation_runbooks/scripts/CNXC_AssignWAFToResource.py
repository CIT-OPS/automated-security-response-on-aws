import boto3
from botocore.config import Config

responses = {}
responses["AssociateWAFResponse"] = []


def connect_to_wafv2(boto_config):
    return boto3.client("wafv2", config=boto_config)


def get_account(boto_config):
    return boto3.client("sts", config=boto_config).get_caller_identity()["Account"]


def associate_wafv2_with_apigateway(ResourceId, web_acl_arn):
    # Initialize the WAFv2 client
    ResourceRegion = ResourceId.split(":")[3]
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=ResourceRegion)
    wafv2_client = connect_to_wafv2(BOTO_CONFIG)

    # Associate the WebACL with the API Gateway stage
    wafv2_client.associate_web_acl(ResourceArn=ResourceId, WebACLArn=web_acl_arn)

    return "OK"


def runbook_handler(event, context):
    # Replace these values with your actual API Gateway ID, stage name, and WAFv2 WebACL ARN
    ResourceId = event["ResourceId"]
    waf_arn = event["WAF_ARN"]

    association_response = associate_wafv2_with_apigateway(ResourceId, waf_arn)

    responses["AssociateWAFResponse"].append(
        {
            "Action": f"Associating {ResourceId} with WAF {waf_arn}",
            "Message": association_response,
        }
    )

    return {"output": "Associate Response", "http_responses": responses}
