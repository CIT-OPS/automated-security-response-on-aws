import json
import logging
import time

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


class LoggingBucketUtils:
    """Utility functions for logging bucket operations."""

    @staticmethod
    def get_elb_principal(region):
        """Get the ELB principal for a specific region."""
        elb_account_ids = {
            "us-east-1": "127311923021",  # N. Virginia
            "us-east-2": "033677994240",  # Ohio
            "us-west-1": "027434742980",  # N. California
            "us-west-2": "797873946194",  # Oregon
            "af-south-1": "098369216593",  # Cape Town
            "ap-east-1": "754344448648",  # Hong Kong
            "ap-southeast-3": "589379963580",  # Jakarta
            "ap-south-1": "718504428378",  # Mumbai
            "ap-northeast-3": "383597477331",  # Osaka
            "ap-northeast-2": "600734575887",  # Seoul
            "ap-southeast-1": "114774131450",  # Singapore
            "ap-southeast-2": "783225319266",  # Sydney
            "ap-northeast-1": "582318560864",  # Tokyo
            "ca-central-1": "985666609251",  # Canada Central
            "eu-central-1": "054676820928",  # Frankfurt
            "eu-west-1": "156460612806",  # Ireland
            "eu-west-2": "652711504416",  # London
            "eu-south-1": "635631232127",  # Milan
            "eu-west-3": "009996457667",  # Paris
            "eu-north-1": "897822967062",  # Stockholm
            "me-south-1": "076674570225",  # Bahrain
            "sa-east-1": "507241528517",  # São Paulo
        }

        elb_account_id = elb_account_ids.get(region)
        if elb_account_id:
            return "arn:aws:iam::" + elb_account_id + ":root"
        else:
            raise ValueError("Invalid region: " + region)

    @staticmethod
    def generate_bucket_name(service_name, account_id, region):
        """Generate standardized bucket names based on service type."""
        if service_name.lower() == "s3":
            # Original S3 server access logging bucket naming convention
            return f"cnxc-s3-server-access-logging-{account_id}-{region}".lower()
        else:
            # Original generic logging bucket naming convention for other services
            return f"asr-logging-{service_name}-{account_id}-{region}".lower()


class UnifiedLoggingBucketManager:
    """Manages creation and configuration of different types of logging buckets."""

    def __init__(self, region):
        self.region = region
        config = Config(region_name=region)
        self.s3_client = boto3.client("s3", config=config)
        self.s3_resource = boto3.resource("s3", config=config)
        self.logger = logging.getLogger(__name__)

    def create_base_bucket(self, bucket_name):
        """Create a base S3 bucket with standard security configurations."""
        try:
            # Common bucket creation logic from both files
            if self.region != "us-east-1":
                try:
                    self.s3_client.create_bucket(
                        Bucket=bucket_name,
                        ACL="private",
                        CreateBucketConfiguration={"LocationConstraint": self.region},
                        ObjectLockEnabledForBucket=False,
                        ObjectOwnership="BucketOwnerEnforced",
                    )
                except ClientError as error:
                    if error.response["Error"]["Code"] == "BucketAlreadyExists":
                        self.logger.info(f"The bucket {bucket_name} already exists")
                    else:
                        self.logger.error(
                            f"Bucket inaccessible {error.response['Error']['Code']}"
                        )
            else:
                try:
                    self.s3_client.create_bucket(
                        Bucket=bucket_name,
                        ACL="private",
                        ObjectLockEnabledForBucket=False,
                        ObjectOwnership="BucketOwnerEnforced",
                    )
                except ClientError as error:
                    if error.response["Error"]["Code"] == "BucketAlreadyExists":
                        self.logger.info(f"The bucket {bucket_name} already exists")
                    else:
                        self.logger.error(
                            f"Bucket inaccessible {error.response['Error']['Code']}"
                        )

            # Apply standard security configurations
            self._apply_security_configurations(bucket_name)

            # Add the exemptLoggingBucket tag
            self._add_exempt_logging_tag(bucket_name)

            return True

        except ClientError as e:
            self.logger.error(f"Error creating bucket: {e}")
            return False

    def _add_exempt_logging_tag(self, bucket_name):
        """Add exemptLoggingBucket tag to the bucket."""
        try:
            self.logger.info(f"Adding exemptLoggingBucket tag to {bucket_name}")
            self.s3_client.put_bucket_tagging(
                Bucket=bucket_name,
                Tagging={
                    "TagSet": [
                        {"Key": "exemptLoggingBucket", "Value": "True"},
                    ]
                },
            )
            self.logger.info(
                f"Successfully tagged {bucket_name} as exemptLoggingBucket=True"
            )
        except ClientError as e:
            self.logger.error(
                f"Error adding exemptLoggingBucket tag to {bucket_name}: {e}"
            )

    def _apply_security_configurations(self, bucket_name):
        """Apply standard security configurations to a bucket."""
        # Common security settings from both files
        self.logger.info(f"Ensuring AES256 on {bucket_name}")
        self.s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
        )

        self.logger.info(f"Ensuring Versioning on {bucket_name}")
        self.s3_client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={"Status": "Enabled"},
        )

        self.logger.info(f"Ensuring Public Access Block on {bucket_name}")
        self.s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

    def create_service_logging_bucket(self, service_name, account_id):
        """Create a logging bucket for a specific AWS service."""
        bucket_name = LoggingBucketUtils.generate_bucket_name(
            service_name, account_id, self.region
        )

        # Create the base bucket
        if not self.create_base_bucket(bucket_name):
            return {
                "message": f"Failed to create logging bucket for {service_name}",
                "status": "FAILED",
            }

        # Apply service-specific policies
        self._configure_service_policies(bucket_name, service_name)

        # Configure lifecycle policies
        self._configure_lifecycle_policy(bucket_name)

        return {
            "message": f"ASR Logging bucket created and/or verified for {service_name}",
            "loggingBucketName": bucket_name,
            "status": "RESOLVED",
        }

    def _configure_service_policies(self, bucket_name, service_name):
        """Configure service-specific bucket policies."""
        # Initialize policy structure
        policy = self._get_existing_policy(bucket_name)
        statements = policy.get("Statement", [])
        update_policy = False

        # Always add SSL-only policy if not present
        ssl_statement = self._get_ssl_only_statement(bucket_name)
        if not self._has_ssl_policy(statements):
            print(f"Adding SSL Only to policy for {bucket_name}")
            statements.append(ssl_statement)
            update_policy = True
        else:
            print(f"{bucket_name} already has a policy statement for SSL Only")

        # Add service-specific policies
        if service_name == "elb":
            if not self._has_elb_policy(statements):
                elb_statement = self._get_elb_statement(bucket_name)
                statements.append(elb_statement)
                update_policy = True
                print(f"Adding ELB Logging to policy for {bucket_name}")
            else:
                print(f"{bucket_name} already has a policy statement for ELB logging")
        elif service_name == "s3":
            # Add S3 server access logging policy if needed
            s3_statement = self._get_s3_logging_statement(bucket_name)
            if not self._has_s3_logging_policy(statements):
                statements.append(s3_statement)
                update_policy = True
                print(f"Adding S3 Server Access Logging to policy for {bucket_name}")
            else:
                print(
                    f"{bucket_name} already has a policy statement for S3 server access logging"
                )

        # Update policy if changes were made
        if update_policy:
            policy["Statement"] = statements
            bucket_policy = json.dumps(policy)
            self.s3_client.put_bucket_policy(Bucket=bucket_name, Policy=bucket_policy)
            print(f"{bucket_name} Policy updated")

    def _get_existing_policy(self, bucket_name):
        """Get existing bucket policy or create a new one."""
        try:
            result = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            return json.loads(result["Policy"])
        except ClientError:
            # Create a new policy if one doesn't exist
            return {"Id": "asrLoggingPolicy", "Version": "2012-10-17", "Statement": []}

    def _has_ssl_policy(self, statements):
        """Check if SSL-only policy exists."""
        for statement in statements:
            try:
                if (
                    statement["Effect"] == "Deny"
                    and statement["Condition"]["Bool"]["aws:SecureTransport"] == "false"
                ):
                    return True
            except (KeyError, TypeError):
                pass
        return False

    def _has_elb_policy(self, statements):
        """Check if ELB logging policy exists."""
        for statement in statements:
            try:
                if (
                    statement["Principal"]["Service"]
                    == "logdelivery.elasticloadbalancing.amazonaws.com"
                ):
                    return True
            except (KeyError, TypeError):
                pass

            try:
                principal = statement["Principal"]["AWS"]
                elb_principals = [
                    "arn:aws:iam::127311923021:root",
                    "arn:aws:iam::033677994240:root",
                    "arn:aws:iam::027434742980:root",
                    "arn:aws:iam::797873946194:root",
                    "arn:aws:iam::098369216593:root",
                    "arn:aws:iam::754344448648:root",
                    "arn:aws:iam::589379963580:root",
                    "arn:aws:iam::718504428378:root",
                    "arn:aws:iam::383597477331:root",
                    "arn:aws:iam::600734575887:root",
                    "arn:aws:iam::114774131450:root",
                    "arn:aws:iam::783225319266:root",
                    "arn:aws:iam::582318560864:root",
                    "arn:aws:iam::985666609251:root",
                    "arn:aws:iam::054676820928:root",
                    "arn:aws:iam::156460612806:root",
                    "arn:aws:iam::652711504416:root",
                    "arn:aws:iam::635631232127:root",
                    "arn:aws:iam::009996457667:root",
                    "arn:aws:iam::897822967062:root",
                    "arn:aws:iam::076674570225:root",
                    "arn:aws:iam::507241528517:root",
                    "arn:aws:iam::048591011584:root",
                    "arn:aws:iam::190560391635:root",
                ]
                if principal in elb_principals:
                    return True
            except (KeyError, TypeError):
                pass
        return False

    def _has_s3_logging_policy(self, statements):
        """Check if S3 server access logging policy exists."""
        for statement in statements:
            try:
                if (
                    statement["Effect"] == "Allow"
                    and statement["Principal"]["Service"] == "logging.s3.amazonaws.com"
                    and "s3:PutObject" in statement["Action"]
                ):
                    return True
            except (KeyError, TypeError):
                pass
        return False

    def _get_ssl_only_statement(self, bucket_name):
        """Get SSL-only policy statement."""
        return {
            "Sid": "asr-S3-Policy-SSLOnly",
            "Action": "s3:*",
            "Effect": "Deny",
            "Resource": [
                f"arn:aws:s3:::{bucket_name}",
                f"arn:aws:s3:::{bucket_name}/*",
            ],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            "Principal": "*",
        }

    def _get_elb_statement(self, bucket_name):
        """Get ELB logging policy statement."""
        try:
            # Try to get region-specific principal
            principal = LoggingBucketUtils.get_elb_principal(self.region)
            print(
                "Using old policy for ELB logging of regions created before August 2022"
            )
            return {
                "Sid": f"asr-ELB-Policy-DO-NOT-MODIFY-{str(int(time.time()))}",
                "Effect": "Allow",
                "Principal": {"AWS": principal},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            }
        except ValueError:
            # Use service principal for newer regions
            print(
                "Using new policy for ELB logging of regions created after August 2022"
            )
            return {
                "Sid": f"asr-ELB-Policy-DO-NOT-MODIFY-{str(int(time.time()))}",
                "Effect": "Allow",
                "Principal": {
                    "Service": "logdelivery.elasticloadbalancing.amazonaws.com"
                },
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            }

    def _get_s3_logging_statement(self, bucket_name):
        """Get S3 server access logging policy statement."""
        return {
            "Sid": f"asr-S3-ServerAccessLogging-Policy-{str(int(time.time()))}",
            "Effect": "Allow",
            "Principal": {
                "Service": "logging.s3.amazonaws.com"
            },  # S3 logging service principal
            "Action": "s3:PutObject",
            "Resource": f"arn:aws:s3:::{bucket_name}/*",
            "Condition": {
                "StringEquals": {"aws:SourceAccount": "${aws:PrincipalAccount}"}
            },
        }

    def _configure_lifecycle_policy(self, bucket_name):
        """Configure lifecycle policies for the bucket."""
        if self._get_bucket_lifecycle(bucket_name) is None:
            print("Adding a 365 day default retention policy")
            self._put_bucket_lifecycle(bucket_name)
        else:
            print("Lifecycle policy found - not altering existing policy")

    def _get_bucket_lifecycle(self, bucket_name):
        """Get bucket lifecycle configuration."""
        try:
            result = self.s3_client.get_bucket_lifecycle_configuration(
                Bucket=bucket_name
            )
            return result
        except ClientError:
            return None
        except Exception as e:
            raise Exception(
                "Unexpected error in _get_bucket_lifecycle function: " + str(e)
            )

    def _put_bucket_lifecycle(self, bucket_name):
        """Put bucket lifecycle configuration."""
        bucket_lifecycle_configuration = self.s3_resource.BucketLifecycleConfiguration(
            bucket_name
        )
        response = bucket_lifecycle_configuration.put(
            LifecycleConfiguration={
                "Rules": [
                    {
                        "Expiration": {"Days": 365},
                        "ID": "DefaultasrRetention",
                        "Status": "Enabled",
                        "Filter": {"Prefix": ""},
                        "NoncurrentVersionExpiration": {"NoncurrentDays": 45},
                        "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 30},
                    }
                ]
            }
        )
        return response


def unified_logging_handler(event, context=None):
    """
    Unified handler for creating logging buckets for different AWS services.

    Args:
        event: Contains parameters including ResourceId or specific service parameters
        context: Lambda context

    Returns:
        Dict containing execution results
    """
    try:
        # Extract service information from ResourceId if available
        region = None
        account_id = None
        service_name = None
        if "ResourceType" in event:
            if event["ResourceType"] == "AwsS3Bucket":
                service_name = "s3"

        if "Region" in event:
            region = event["Region"]

        if "ResourceId" in event:
            resource_id = event["ResourceId"]

        if ":" in resource_id:
            resource_split = resource_id.split(":")
            service_name = resource_split[2]
            if service_name == "elasticloadbalancing":
                service_name = "elb"

        if region is None or region == "":
            region = event.get("Region")
        if account_id is None or account_id == "":
            account_id = event.get("AccountId")
        if service_name is None or service_name == "":
            service_name = event.get("ServiceName")

        print(f"Service: {service_name}, Region: {region}, Account: {account_id}")
        if not all([service_name, region, account_id]):
            raise ValueError("Missing required parameters")

        # Create and configure the logging bucket
        manager = UnifiedLoggingBucketManager(region)
        return manager.create_service_logging_bucket(service_name, account_id)

    except Exception as e:
        logging.error(f"Error in unified_logging_handler: {str(e)}")
        raise RuntimeError(f"Error in unified_logging_handler: {str(e)}")


# For backward compatibility with the original functions
def runbook_handler(event, context):
    """Legacy handler function for backward compatibility."""
    return unified_logging_handler(event, context)


# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

# For local testing
if __name__ == "__main__":
    # Example event for testing
    test_event = {
        "AccountId": "211125410042",
        "ResourceId": "asr-test-bucket-kpp-2",
        "Region": "us-east-1",
        "ResourceType": "AwsS3Bucket",
    }
    print(unified_logging_handler(test_event))
