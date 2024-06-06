import boto3


def enableAccessLogging(s3, bucketName, storageBucket, targetPrefix):
    print(f"Now setting logging on {bucketName} --> {storageBucket}/{targetPrefix}")
    return s3.put_bucket_logging(
        Bucket=bucketName,
        BucketLoggingStatus={
            "LoggingEnabled": {
                "TargetBucket": storageBucket,
                "TargetPrefix": targetPrefix,
            }
        },
    )


def runbook_handler(event, context):
    s3_client = boto3.client("s3")
    bucketName = event["BucketName"]
    destBucket = event["LoggingBucketName"]
    targetPrefix = "access_logs/s3/" + bucketName + "/"

    if bucketName == destBucket:
        return {
            "output": {
                "message": "This bucket is exempt from logging as it would create a circular log effect",
                "resourceBucketName": bucketName,
                "LoggingBucketName": destBucket,
                "LoggingPrefix": targetPrefix,
                "status": "SUPPRESSED",
            }
        }

    enableAccessLogging(s3_client, bucketName, destBucket, targetPrefix)
    return {
        "output": {
            "message": "Server Access Logging Successfully Set.",
            "resourceBucketName": bucketName,
            "LoggingBucketName": destBucket,
            "LoggingPrefix": targetPrefix,
            "status": "RESOLVED",
        }
    }
