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
        try:
          bucket = s3_client.create_bucket(
            Bucket=bucket_name,
            ACL='private',
            CreateBucketConfiguration={ 
              'LocationConstraint': region
            },
            ObjectLockEnabledForBucket=False,
            ObjectOwnership='BucketOwnerEnforced'
          ) 
        except botocore.exceptions.ClientError as error:
          if error.response['Error']['Code'] == 'BucketAlreadyExists':
              logging.info(f"The server access log bucket {bucket_name} already exists")
          else:
              logging.error(f"Server access log bucket inaccessable {error.response['Error']['Code']}")
          pass
    else:
        try:
          bucket = s3_client.create_bucket(
            Bucket=bucket_name,
            ACL='private',
            ObjectLockEnabledForBucket=False,
            ObjectOwnership='BucketOwnerEnforced'
          ) 
        except botocore.exceptions.ClientError as error:
          if error.response['Error']['Code'] == 'BucketAlreadyExists':
              logging.info(f"The server access log bucket {bucket_name} already exists")
          else:
              logging.error(f"Server access log bucket inaccessable {error.response['Error']['Code']}")
          pass
    
    logging.info(f"Ensuring AES256 on {bucket_name}")
    response = s3_client.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        },
    )

    logging.info(f"Ensuring Versioning on {bucket_name}")   
    response = s3_client.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={
            'Status': 'Enabled'
        },
    )
    
    logging.info(f"Ensuring Public Access Block on {bucket_name}") 
    response = s3_client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )
  except ClientError as e:
    logging.error(e)
    return False
  
  return True

def updateBucketPolicies(s3_client, s3_resource, serviceName, region, storageBucket):
  # Get the existing policy document
  # Retrieve the policy of the specified bucket
  
  #bucketArn = 'arn:aws:s3:::'+bucketName+'/*'
  matchedELBLogging = False
  matchedSSL = False
  updatePolicy = False
  statements = []
  try:
    result = s3_client.get_bucket_policy(Bucket=storageBucket)
    policy = eval(result['Policy'])
    statements = policy['Statement']
    for statement in statements:
        # Elastic Load Balancer
        try:
            if statement['Principal']['Service'] == 'logdelivery.elasticloadbalancing.amazonaws.com':
                matchedELBLogging = True
        except:
            pass
        
        try:
            if statement['Principal']['AWS'] == 'arn:aws:iam::127311923021:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::033677994240:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::027434742980:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::797873946194:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::098369216593:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::754344448648:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::589379963580:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::718504428378:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::383597477331:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::600734575887:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::114774131450:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::783225319266:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::582318560864:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::985666609251:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::054676820928:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::156460612806:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::652711504416:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::635631232127:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::009996457667:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::897822967062:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::076674570225:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::507241528517:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::048591011584:root' or \
            statement['Principal']['AWS'] == 'arn:aws:iam::190560391635:root':
                matchedELBLogging = True
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
    policy = json.loads('{ "Id": "SharrLoggingPolicy", "Version": "2012-10-17","Statement": []}')
    updatePolicy = True
    statements = []
    
  if matchedSSL:
    print(storageBucket + ' already has a policy statement for SSL Only')
  else:
    print('Adding SSL Only to policy')
    newStatement = json.loads('{"Sid": "SHARR-S3-Policy-SSLOnly","Action": "s3:*","Effect": "Deny","Resource": ["arn:aws:s3:::'+storageBucket+'","arn:aws:s3:::'+storageBucket+'/*"],"Condition": {"Bool": {"aws:SecureTransport": "false"}},"Principal": "*"}')
    statements.append(newStatement)
    updatePolicy = True
    
  if serviceName == 'elb':
    if matchedELBLogging:
        print(storageBucket + ' already has a policy statement for ELB logging')
    else:
        print('Adding ELB Logging to policy')
        
        newStatement = json.loads('{"Sid": "SHARR-ELB-Policy-DO-NOT-MODIFY-'+str(int(time.time()))+'", "Effect":"Allow","Principal":{"AWS": "'+determineELBPrincipal(region)+'"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::'+storageBucket+'/*"}')
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

def determineELBPrincipal(region):
    elbAccountId = ''
    if region == 'us-east-1':
       elbAccountId = '127311923021'
    elif region == 'us-east-2':
       elbAccountId = '033677994240'
    elif region == 'us-west-1':
       elbAccountId = '027434742980'
    elif region == 'us-west-2':
       elbAccountId = '797873946194'
    elif region == 'ca-central-1':
       elbAccountId = '985666609251'
    elif region == 'ap-southeast-2':
       elbAccountId = '783225319266'
    elif region == 'eu-west-2':
       elbAccountId = '652711504416'
    return "arn:aws:iam::"+elbAccountId+":root"

def runbook_handler(event, context):
  ResourceId = event['ResourceId']  # arn:aws:elasticloadbalancing:us-east-1:857932575317:loadbalancer/app/XPVA-TstAR2-DID-DEV1/25d1f4f34ae00664
  ResourceSplit = ResourceId.split(":")
  serviceName = ResourceSplit[2]
  if serviceName == 'elasticloadbalancing':
    serviceName = 'elb'
  region = ResourceSplit[3]
  AwsAccountId = ResourceSplit[4]
  destBucket = 'sharr-logging-' + serviceName + '-' + AwsAccountId + '-' + region.lower()
  my_config = Config(region_name = region)
  s3_client = boto3.client('s3', config=my_config)
  s3_resource = boto3.resource('s3', config=my_config)

  # Create the Logging Bucket
  create_bucket(s3_client, destBucket, region)

  # Update the Bucket Policies
  updateBucketPolicies(s3_client, s3_resource, serviceName, region, destBucket)

  return {
        'message': 'Logging bucket created and or verified',
        'loggingBucketName': destBucket,
        'status': 'RESOLVED'
  }

if __name__ == "__main__":
    event = {
       "ResourceId": "arn:aws:elasticloadbalancing:us-east-1:924746602103:loadbalancer/app/XPVA-SYNAPS-SYNAPS-DEV1/a14b93bcfe33d728",
    }
    result = runbook_handler(event,"")
    print(result)