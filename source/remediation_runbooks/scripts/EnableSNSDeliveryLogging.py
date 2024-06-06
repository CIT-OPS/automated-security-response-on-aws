import json

import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard"})


def runbook_handler(event, context):
    responses = {}
    responses["EnableSNSDeliveryLoggingResponse"] = []
    SNSSuccessFeedback = create_role_if_not_existing("SNSSuccessFeedback")
    SNSFailureFeedback = create_role_if_not_existing("SNSFailureFeedback")
    responses["EnableSNSDeliveryLoggingResponse"].append(
        "SNSSuccessFeedback is " + SNSSuccessFeedback
    )
    responses["EnableSNSDeliveryLoggingResponse"].append(
        "SNSFailureFeedback is " + SNSFailureFeedback
    )
    ResourceId = event["ResourceId"]
    Region = event["Region"]
    responses["EnableSNSDeliveryLoggingResponse"].append("Resource ID is " + ResourceId)
    client = connect_to_sns(BOTO_CONFIG, Region)
    response = client.set_topic_attributes(
        TopicArn=ResourceId,
        AttributeName="ApplicationSuccessFeedbackRoleArn",
        AttributeValue=SNSSuccessFeedback,
    )
    responses["EnableSNSDeliveryLoggingResponse"].append(
        "Setting ApplicationSuccessFeedbackRoleArn "
        + json.dumps(response["ResponseMetadata"])
    )
    response = client.set_topic_attributes(
        TopicArn=ResourceId,
        AttributeName="ApplicationSuccessFeedbackSampleRate",
        AttributeValue="100",
    )
    responses["EnableSNSDeliveryLoggingResponse"].append(
        "Setting ApplicationSuccess Rate to 100 "
        + json.dumps(response["ResponseMetadata"])
    )
    response = client.set_topic_attributes(
        TopicArn=ResourceId,
        AttributeName="ApplicationFailureFeedbackRoleArn",
        AttributeValue=SNSFailureFeedback,
    )
    responses["EnableSNSDeliveryLoggingResponse"].append(
        "Setting ApplicationFailureFeedbackRole Arn "
        + json.dumps(response["ResponseMetadata"])
    )
    print(responses)
    return responses


def create_role_if_not_existing(role_name):
    client = connect_to_iam(BOTO_CONFIG)
    try:
        response = client.get_role(RoleName=role_name)
        if "Role" in response:
            return response["Role"]["Arn"]
    except Exception:
        "Role " + role_name + " does not exist.  Creating"
        pass

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    # Create the role
    response = client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description="Role created by SHARR/ASR to remediate SNS.2",
    )

    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "logs:PutMetricFilter",
                    "logs:PutRetentionPolicy",
                ],
                "Resource": ["*"],
            }
        ],
    }

    response = client.put_role_policy(
        RoleName=role_name,
        PolicyName="sns_cloudwatch_permissions",
        PolicyDocument=json.dumps(permissions_policy),
    )

    response = client.get_role(RoleName=role_name)
    if "Role" in response:
        return response["Role"]["Arn"]
    else:
        exit("Role not created")


def connect_to_iam(boto_config):
    return boto3.client("iam", config=boto_config)


def connect_to_sns(boto_config, region):
    return boto3.client("sns", config=boto_config, region_name=region)


if __name__ == "__main__":
    event = {
        "ResourceId": "arn:aws:sns:us-west-2:234772128127:amazonConnectTopic",
        "Region": "us-west-2",
    }
    result = runbook_handler(event, "")
    print(result)
