import json
import logging
import time

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def get_bucket_lifecycle_of_s3(s3_client, bucket_name):
    try:
        result = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
    except ClientError:
        return None
    except Exception as e:
        raise Exception(
            "Unexpected error in get_bucket_lifecycle_of_s3 function: " + e.__str__()
        )
    return result


def put_bucket_lifecycle_of_s3(s3_resource, bucket_name):
    # s3 = boto3.resource('s3')
    bucket_lifecycle_configuration = s3_resource.BucketLifecycleConfiguration(
        bucket_name
    )
    response = bucket_lifecycle_configuration.put(
        LifecycleConfiguration={
            "Rules": [
                {
                    "Expiration": {"Days": 365},
                    "ID": "DefaultASRRetention",
                    "Status": "Enabled",
                    "Filter": {"Prefix": ""},
                    "NoncurrentVersionExpiration": {"NoncurrentDays": 45},
                    "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 30},
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
        if region != "us-east-1":
            try:
                s3_client.create_bucket(
                    Bucket=bucket_name,
                    ACL="private",
                    CreateBucketConfiguration={"LocationConstraint": region},
                    ObjectLockEnabledForBucket=False,
                    ObjectOwnership="BucketOwnerEnforced",
                )
            except ClientError as error:
                if error.response["Error"]["Code"] == "BucketAlreadyExists":
                    logging.info(
                        f"The server access log bucket {bucket_name} already exists"
                    )
                else:
                    logging.error(
                        f"Server access log bucket inaccessable {error.response['Error']['Code']}"
                    )
                pass
        else:
            try:
                s3_client.create_bucket(
                    Bucket=bucket_name,
                    ACL="private",
                    ObjectLockEnabledForBucket=False,
                    ObjectOwnership="BucketOwnerEnforced",
                )
            except ClientError as error:
                if error.response["Error"]["Code"] == "BucketAlreadyExists":
                    logging.info(
                        f"The server access log bucket {bucket_name} already exists"
                    )
                else:
                    logging.error(
                        f"Server access log bucket inaccessable {error.response['Error']['Code']}"
                    )
                pass

        logging.info(f"Ensuring AES256 on {bucket_name}")
        s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
        )

        logging.info(f"Ensuring Versioning on {bucket_name}")
        s3_client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={"Status": "Enabled"},
        )

        logging.info(f"Ensuring Public Access Block on {bucket_name}")
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
    except ClientError as e:
        logging.error(e)
        return False

    return True


def updateBucketPolicies(s3_client, s3_resource, bucketName, storageBucket):
    # Get the existing policy document
    # Retrieve the policy of the specified bucket

    # bucketArn = "arn:aws:s3:::" + bucketName + "/*"
    matchedLogging = False
    matchedSSL = False
    # matchedTLS = False
    updatePolicy = False
    statements = []
    try:
        result = s3_client.get_bucket_policy(Bucket=storageBucket)
        policy = eval(result["Policy"])
        statements = policy["Statement"]
        for statement in statements:

            try:
                if statement["Principal"]["Service"] == "logging.s3.amazonaws.com":
                    matchedLogging = True
            except Exception:
                pass

            try:
                if (
                    statement["Effect"] == "Deny"
                    and statement["Condition"]["Bool"]["aws:SecureTransport"] == "false"
                ):
                    matchedSSL = True
            except Exception:
                pass

    except ClientError as error:
        print(error.response["Error"]["Code"])
        print("Creating a new policy")
        policy = json.loads(
            '{ "Id": "ASRNewBucketPolicy", "Version": "2012-10-17","Statement": []}'
        )
        updatePolicy = True
        statements = []

    if matchedSSL:
        print(storageBucket + " already has a policy statement for SSL Only")
    else:
        print("Adding SSL Only to policy")
        newStatement = json.loads(
            '{"Sid": "ASRS3PolicyStmtSSLOnly","Action": "s3:*","Effect": "Deny","Resource": ["arn:aws:s3:::'
            + storageBucket
            + '","arn:aws:s3:::'
            + storageBucket
            + '/*"],"Condition": {"Bool": {"aws:SecureTransport": "false"}},"Principal": "*"}'
        )
        statements.append(newStatement)
        updatePolicy = True

    if matchedLogging:
        print(
            storageBucket
            + " already has a policy statement to allow logging.s3.amazonaws.com for "
            + bucketName
        )
    else:
        print("Adding Logging to policy")
        newStatement = json.loads(
            '{"Sid": "ASRS3PolicyStmt-DO-NOT-MODIFY-'
            + str(int(time.time()))
            + '", "Effect":"Allow","Principal":{"Service": "logging.s3.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::'
            + storageBucket
            + '/*"}'
        )
        statements.append(newStatement)
        updatePolicy = True

    if updatePolicy:
        policy["Statement"] = statements
        # Convert the policy from JSON dict to string
        bucket_policy = json.dumps(policy)
        # Set the new policy
        s3_client.put_bucket_policy(Bucket=storageBucket, Policy=bucket_policy)
        print(storageBucket + " Policy updated")

    # print(get_bucket_lifecycle_of_s3(s3, storageBucket))
    if get_bucket_lifecycle_of_s3(s3_client, storageBucket) is None:
        print("Adding a 365 day default retention policy")
        print(put_bucket_lifecycle_of_s3(s3_resource, storageBucket))

    else:
        print("Lifecycle policy found - not altering existing policy")
        # print(get_bucket_lifecycle_of_s3(s3, storageBucket))

    return


def runbook_handler(event, context):
    # serviceName = "s3"  # default
    try:
        bucketName = event["BucketName"]
    except Exception:
        bucketName = ""
        # serviceName = event["logType"]
        pass

    region = event["Region"]
    AwsAccountId = event["AccountId"]
    destBucket = "cnxc-s3-server-access-logging-" + AwsAccountId + "-" + region
    my_config = Config(region_name=region)
    s3_client = boto3.client("s3", config=my_config)
    s3_resource = boto3.resource("s3", config=my_config)

    # Create the Logging Bucket
    create_bucket(s3_client, destBucket, region)

    # Update the Bucket Policies
    updateBucketPolicies(s3_client, s3_resource, bucketName, destBucket)

    return {
        "message": "Logging bucket created and or verified",
        "loggingBucketName": destBucket,
        "status": "RESOLVED",
    }


if __name__ == "__main__":
    event = {
        "BucketName": "needs-s39",
        "AccountId": "332241576022",
        "Region": "us-east-1",
    }
    result = runbook_handler(event, "")
    print(result)
