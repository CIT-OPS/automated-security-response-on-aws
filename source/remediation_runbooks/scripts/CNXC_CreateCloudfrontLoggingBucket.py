import json
import logging

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
                    # ACL='private',
                    CreateBucketConfiguration={"LocationConstraint": region},
                    ObjectLockEnabledForBucket=False,
                    ObjectOwnership="BucketOwnerPreferred",
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
                    # ACL='private',
                    ObjectLockEnabledForBucket=False,
                    ObjectOwnership="BucketOwnerPreferred",
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

        # See Permissions required to configure standard logging and to access your log files
        # https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html
        logging.info(f"Granting Logging Account ACL on {bucket_name}")
        print(bucket_name)
        existingACL = s3_client.get_bucket_acl(Bucket=bucket_name)
        existingACL.pop("ResponseMetadata")

        # printJson(existingACL)
        # exit()
        foundGrant = False
        newGrants = []
        for grant in existingACL["Grants"]:

            if (
                grant["Grantee"]["ID"]
                == "c4c1ede66af53448b93c283ce9448c4ba468c9432aa01d700d3878632f77d2d0"
            ):
                grant = {
                    "Grantee": {
                        "ID": "c4c1ede66af53448b93c283ce9448c4ba468c9432aa01d700d3878632f77d2d0",
                        "DisplayName": "AWS Logging",
                        "Type": "CanonicalUser",
                    },
                    "Permission": "WRITE",
                }
                foundGrant = True
            newGrants.append(grant)
        if foundGrant is False:
            newGrants.append(
                {
                    "Grantee": {
                        "ID": "c4c1ede66af53448b93c283ce9448c4ba468c9432aa01d700d3878632f77d2d0",
                        "DisplayName": "AWS Logging",
                        "Type": "CanonicalUser",
                    },
                    "Permission": "WRITE",
                }
            )
        existingACL["Grants"] = newGrants

        s3_client.put_bucket_acl(
            AccessControlPolicy=existingACL,
            Bucket=bucket_name,
        )
    except ClientError as e:
        logging.error(e)
        return False

    return True


def updateBucketPolicies(s3_client, s3_resource, serviceName, region, storageBucket):
    # Get the existing policy document
    # Retrieve the policy of the specified bucket

    # bucketArn = 'arn:aws:s3:::'+bucketName+'/*'
    # matchedELBLogging = False
    matchedSSL = False
    updatePolicy = False
    statements = []
    try:
        result = s3_client.get_bucket_policy(Bucket=storageBucket)
        policy = eval(result["Policy"])
        statements = policy["Statement"]
        for statement in statements:
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
            '{ "Id": "ASRLoggingPolicy", "Version": "2012-10-17","Statement": []}'
        )
        updatePolicy = True
        statements = []

    if matchedSSL:
        print(storageBucket + " already has a policy statement for SSL Only")
    else:
        print("Adding SSL Only to policy")
        newStatement = json.loads(
            '{"Sid": "ASR-S3-Policy-SSLOnly","Action": "s3:*","Effect": "Deny","Resource": ["arn:aws:s3:::'
            + storageBucket
            + '","arn:aws:s3:::'
            + storageBucket
            + '/*"],"Condition": {"Bool": {"aws:SecureTransport": "false"}},"Principal": "*"}'
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
    ResourceId = event["ResourceId"]
    ResourceSplit = ResourceId.split(":")
    serviceName = ResourceSplit[2]
    region = event["Region"]
    AwsAccountId = ResourceSplit[4]
    destBucket = "asr-logging-" + serviceName + "-" + AwsAccountId + "-" + region
    destBucket = destBucket.lower()

    my_config = Config(region_name=region)
    s3_client = boto3.client("s3", config=my_config)
    s3_resource = boto3.resource("s3", config=my_config)

    # Create the Logging Bucket
    create_bucket(s3_client, destBucket, region)

    # Update the Bucket Policies
    updateBucketPolicies(s3_client, s3_resource, serviceName, region, destBucket)

    return {
        "message": "Logging bucket created and or verified",
        "loggingBucketName": destBucket,
        "status": "RESOLVED",
    }


def printJson(object):
    json_formatted_str = json.dumps(object, indent=2)
    print(json_formatted_str)
    return


if __name__ == "__main__":
    event = {
        "ResourceId": "arn:aws:cloudfront::619391186421:distribution/E32G6YNRXCGN90",
        "Region": "us-east-1",
    }
    result = runbook_handler(event, "")
    print(result)
