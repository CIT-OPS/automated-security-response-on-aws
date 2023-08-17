import logging
import copy
import json
import time
from pprint import pprint
import botocore
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config

def get_bucket_lifecycle_of_s3(s3_client, bucket_name):
  try:
      result = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
  except ClientError as e:
      return None
  except Exception as e:
      raise Exception( "Unexpected error in get_bucket_lifecycle_of_s3 function: " + e.__str__())
  return result

def put_bucket_lifecycle_of_s3(s3_resource, bucket_name):
  #s3 = boto3.resource('s3')
  bucket_lifecycle_configuration = s3_resource.BucketLifecycleConfiguration(bucket_name)
  response = bucket_lifecycle_configuration.put(
    LifecycleConfiguration={
        'Rules': [
             {
               "Expiration":{
                  "Days":365
                },
                "ID":"DefaultSHARRRetention",
                "Status":"Enabled",
                "Filter": {
                  "Prefix": ""
                },
                "NoncurrentVersionExpiration":{
                    "NoncurrentDays":45
                },
                "AbortIncompleteMultipartUpload":{
                  "DaysAfterInitiation":30
                }
              }
        ]
    }
  )  
  return response

def create_bucket(s3_client, bucket_name, region):
  """Create an S3 bucket in a specified region

  If a region is not specified, the bucket is created in the S3 default
  region (us-east-1).

  :param bucket_name: Bucket to create
  :param region: String region to create bucket in, e.g., 'us-west-2'
  :return: True if bucket created, else False
  """

  # Create bucket
  try:
    if region != 'us-east-1':
        bucket = s3_client.create_bucket(
          Bucket=bucket_name,
          ACL='private',
          CreateBucketConfiguration={ 
            'LocationConstraint': region
          },
          ObjectLockEnabledForBucket=False,
          ObjectOwnership='BucketOwnerEnforced'
        ) 
        logging.info(bucket)
    else:
        bucket = s3_client.create_bucket(
          Bucket=bucket_name,
          ACL='private',
          ObjectLockEnabledForBucket=False,
          ObjectOwnership='BucketOwnerEnforced'
        ) 
        logging.info(bucket)
    
    response = s3_client.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        },
    )   
    response = s3_client.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={
            'Status': 'Enabled'
        },
    )
    
    response = s3_client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )
    print(response)
    
  except ClientError as e:
    logging.error(e)
    return False
  return True

def updateBucketPolicies(s3_client, s3_resource, bucketName, storageBucket, targetPrefix):
  # Get the existing policy document
  # Retrieve the policy of the specified bucket
  
  bucketArn = 'arn:aws:s3:::'+bucketName+'/*'
  matchedLogging = False
  matchedSSL = False
  updatePolicy = False
  statements = []
  try:
    result = s3_client.get_bucket_policy(Bucket=storageBucket)
    policy = eval(result['Policy'])
    statements = policy['Statement']
    for statement in statements:

      try:
        if statement['Principal']['Service'] == 'logging.s3.amazonaws.com':
          matchedLogging = True
      except:
        pass

      try:
        if statement['Effect'] == 'Deny' and statement['Condition']['Bool']['aws:SecureTransport'] == "false":
          matchedSSL = True
      except:
        pass


    
  except botocore.exceptions.ClientError as error:
    print(error.response['Error']['Code'])
    print('Creating a new policy')
    policy = json.loads('{ "Id": "SharrNewBucketPolicy", "Version": "2012-10-17","Statement": [{ "Sid": "AllowSSLRequestsOnly","Action": "s3:*","Effect": "Deny","Resource": ["arn:aws:s3:::'+storageBucket+'","arn:aws:s3:::'+storageBucket+'/*" ], "Condition": {"Bool": { "aws:SecureTransport": "false"  } },  "Principal": "*"  }]}')
    updatePolicy = True
    statements = []
    
  if matchedSSL:
    print(storageBucket + ' already has a policy statement for SSL Only')
  else:
    print('Adding SSL Only to policy')
    newStatement = json.loads('{"Sid": "SHARRS3PolicyStmtSSLOnly","Action": "s3:*","Effect": "Deny","Resource": ["arn:aws:s3:::'+storageBucket+'","arn:aws:s3:::'+storageBucket+'/*"],"Condition": {"Bool": {"aws:SecureTransport": "false"}},"Principal": "*"}')
    statements.append(newStatement)
    updatePolicy = True
    
  if matchedLogging:
    print(storageBucket + ' already has a policy statement to allow logging.s3.amazonaws.com for '+ bucketName)
  else:
    print('Adding Logging to policy')
    newStatement = json.loads('{"Sid": "SHARRS3PolicyStmt-DO-NOT-MODIFY-'+str(int(time.time()))+'", "Effect":"Allow","Principal":{"Service": "logging.s3.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::'+storageBucket+'/*"}')
    statements.append(newStatement)
    updatePolicy = True
    
  if updatePolicy:
    policy['Statement'] = statements
    # Convert the policy from JSON dict to string
    bucket_policy = json.dumps(policy)
    # Set the new policy
    s3_client.put_bucket_policy(Bucket=storageBucket, Policy=bucket_policy)
    print(storageBucket+' Policy updated')
  
  #print(get_bucket_lifecycle_of_s3(s3, storageBucket))
  if get_bucket_lifecycle_of_s3(s3_client, storageBucket) == None:
    print("Adding a 365 day default retention policy")
    print(put_bucket_lifecycle_of_s3(s3_resource,storageBucket))
    
  else:
    print("Lifecycle policy found - not altering existing policy")
    #print(get_bucket_lifecycle_of_s3(s3, storageBucket))  
    
  return

def lambda_handler(event, context):
  resourceId = event['Resource']['Id']
  region = event['Finding']['Region']
  bucketArray = resourceId.split(':')
  fixmeBucket = bucketArray[-1]
  AwsAccountId = event['Finding']['AwsAccountId']
  destBucket = 'cnxc-s3-server-access-logging-' + AwsAccountId + '-' + region
  targetPrefix = fixmeBucket+'/'
  
  my_config = Config(
    region_name = event['Finding']['Region'],
  )
  
  s3_client = boto3.client('s3', config=my_config)
  s3_resource = boto3.resource('s3', config=my_config)

  print(fixmeBucket, destBucket, targetPrefix)
  if fixmeBucket == destBucket:
      return {
        'output':
          {
            'message': 'This bucket is exempt from logging as it would create a circular log effect',
          }
      }
  create_bucket(s3_client, destBucket, region)
  updateBucketPolicies(s3_client, s3_resource, fixmeBucket, destBucket, targetPrefix)
  return {
    'output':
      {
        'message': 'Bucket created/updated',
      }
  }