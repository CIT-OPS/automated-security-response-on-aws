# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

def connect_to_dynamodb(region, boto_config):
    return boto3.client('dynamodb', region_name=region, config=boto_config)

def lambda_handler(event, context):
    """
    remediates DynamoDB.2 by enabling Point In Time Recovery
    On success returns a string map
    On failure returns NoneType
    """
    boto_config = Config(
        retries ={
          'mode': 'standard'
        }
    )
    
    splitEnv = event['tableArn'].split(":")
    splitTable = splitEnv[5].split("/")
    
    if (splitTable[0] != 'table' and splitTable[0] != 'global-table') or splitEnv[0] != 'arn' or splitEnv[1] != 'aws' or splitEnv[2] != 'dynamodb':
        print("Invalid DynamoDB arn of ",event['tableArn'])
        return {
            "response": {
                "message": f'Invalid DynamoDB arn {event["tableArn"]}',
                "status": "Failed"
            }
        }
        
    tablename = splitTable[1]
    region = splitEnv[3]
    account = splitEnv[4]
    #print(account,region,tablename)

    ddb_client = connect_to_dynamodb(region, boto_config)
    
    try:
        ddb_client.update_continuous_backups(
            TableName=tablename,
            PointInTimeRecoverySpecification={
                'PointInTimeRecoveryEnabled': True
            }
        )
        return {
            "response": {
                "message": f'Enabled PITR on {tablename}',
                "status": "Success"
            }
        }
    except Exception as e:
        exit(f'Error setting PITR: {str(e)}')
