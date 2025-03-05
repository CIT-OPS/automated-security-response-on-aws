import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def connect_to_dynamodb(region, boto_config):
    return boto3.client("dynamodb", region_name=region, config=boto_config)


def lambda_handler(event, context):
    """
    remediates DynamoDB.6 by enabling Delete Protection
    On success returns a string map
    On failure returns NoneType
    """
    boto_config = Config(retries={"mode": "standard"})

    splitEnv = event["tableArn"].split(":")
    splitTable = splitEnv[5].split("/")

    if (
        (splitTable[0] != "table" and splitTable[0] != "global-table")
        or splitEnv[0] != "arn"
        or splitEnv[1] != "aws"
        or splitEnv[2] != "dynamodb"
    ):
        print("Invalid DynamoDB arn of ", event["tableArn"])
        return {
            "response": {
                "message": f'Invalid DynamoDB arn {event["tableArn"]}',
                "status": "Failed",
            }
        }

    table_name = splitTable[1]
    region = splitEnv[3]

    dynamodb = connect_to_dynamodb(region, boto_config)

    try:
        # Describe the table to get its current settings
        table_description = dynamodb.describe_table(TableName=table_name)

        # Extract the current delete protection status
        delete_protection_enabled = table_description["Table"][
            "DeletionProtectionEnabled"
        ]

        # Check if delete protection is already enabled
        if delete_protection_enabled:
            print(f"Delete protection is already enabled for table '{table_name}'")
            return {
                "response": {
                    "message": f"Delete protection is already enabled for table '{table_name}'",
                    "status": "Success",
                }
            }
        else:
            # Enable delete protection
            response = dynamodb.update_table(
                TableName=table_name, DeletionProtectionEnabled=True
            )
            print(f"Delete protection enabled for table '{table_name}'")
            return {
                "response": {
                    "message": f"Delete protection enabled for table '{table_name}'",
                    "status": "Success",
                }
            }
            return response

    except ClientError as e:
        print(f"Error enabling delete protection: {e}")
        return None
