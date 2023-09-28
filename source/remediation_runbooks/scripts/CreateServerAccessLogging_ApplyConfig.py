import logging
import copy
import json
import time
from pprint import pprint
import botocore
import boto3
from botocore.exceptions import ClientError


def enableAccessLogging(s3, bucketName, storageBucket, targetPrefix):
  print(f"Now setting logging on {bucketName} --> {storageBucket}/{targetPrefix}")
  return s3.put_bucket_logging(
      Bucket=bucketName,
      BucketLoggingStatus={
          'LoggingEnabled': {
              'TargetBucket': storageBucket,
              'TargetPrefix': targetPrefix
          }
      }
  )

def runbook_handler(event, context):
  s3_client = boto3.client('s3')
  bucketName = event['BucketName']
  destBucket = event['LoggingBucketName']
  targetPrefix = 'access_logs/s3/'+bucketName+'/'
  
  if bucketName == destBucket:
      return {
        'output':
          {
            'message': 'This bucket is exempt from logging as it would create a circular log effect',
            'resourceBucketName': bucketName,
            'LoggingBucketName': destBucket,
            'LoggingPrefix': targetPrefix,
            'status': 'SUPPRESSED'
          }
      }

  output = enableAccessLogging(s3_client, bucketName, destBucket, targetPrefix)
  return {
    'output':
      {
        'message': 'Server Access Logging Successfully Set.',
        'resourceBucketName': bucketName,
        'LoggingBucketName': destBucket,
        'LoggingPrefix': targetPrefix,
        'status': 'RESOLVED'
      }
  }

# if __name__ == "__main__":
#     event = {
#         "AutomationAssumeRole": 'arn:aws:iam::194039877044:role/StupidFingSubstitution',
#         "BucketName": 'cnxc-inventory',
#         "loggingBucketName": 'cnxc-s3-server-access-logging-194039877044-us-east-1',
#     }
#     result = lambda_handler(event,"")
#     print(result)
    