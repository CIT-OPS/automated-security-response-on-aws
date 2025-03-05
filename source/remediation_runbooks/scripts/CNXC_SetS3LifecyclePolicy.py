# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import boto3  # type: ignore
from botocore.config import Config  # type: ignore

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_s3():
    return boto3.client("s3", config=BOTO_CONFIG)


def lambda_handler(event, _):
    bucket_name = event["BucketName"]
    # target_transition_days = event["TargetTransitionDays"]
    # target_expiration_days = event["TargetExpirationDays"]
    # target_transition_storage_class = event["TargetTransitionStorageClass"]
    rule_id = "S3.13 Default CNXC Lifecycle Rule"
    s3 = connect_to_s3()

    rule1 = {
        "Rule": {
            "ID": "Rule 1",
            "Filter": {
                "And": {
                    "Tag": [
                        {"Key": "Expiration", "Value": "30"},
                    ]
                }
            },
            "Status": "Enabled",
            "Expiration": {"Days": 30},
        }
    }

    rule2 = {
        "Rule": {
            "ID": "Rule 2",
            "Filter": {
                "And": {
                    "Tag": [
                        {"Key": "Expiration", "Value": "45"},
                    ]
                }
            },
            "Status": "Enabled",
            "Expiration": {"Days": 45},
        }
    }

    rule3 = {
        "Rule": {
            "ID": "Rule 3",
            "Filter": {
                "And": {
                    "Tag": [
                        {"Key": "Expiration", "Value": "90"},
                    ]
                }
            },
            "Status": "Enabled",
            "Expiration": {"Days": 90},
        }
    }

    rule4 = {
        "Rule": {
            "ID": "Rule 4",
            "Filter": {
                "And": {
                    "Tag": [
                        {"Key": "Expiration", "Value": "180"},
                    ]
                }
            },
            "Status": "Enabled",
            "Expiration": {"Days": 180},
        }
    }

    rule5 = {
        "Rule": {
            "ID": "Rule 5",
            "Filter": {
                "And": {
                    "Tag": [
                        {"Key": "Expiration", "Value": "1Y"},
                    ]
                }
            },
            "Status": "Enabled",
            "Expiration": {"Years": 1},
        }
    }

    rule6 = {
        "Rule": {
            "ID": "Rule 6",
            "Filter": {
                "And": {
                    "Tag": [
                        {"Key": "Expiration", "Value": "2Y"},
                    ]
                }
            },
            "Status": "Enabled",
            "Expiration": {"Years": 2},
        }
    }

    rule7 = {
        "Rule": {
            "ID": "Rule 7",
            "Filter": {
                "And": {
                    "Tag": [
                        {"Key": "Expiration", "Value": "3Y"},
                    ]
                }
            },
            "Status": "Enabled",
            "Expiration": {"Years": 3},
        }
    }

    lifecycle_policy = {
        "Rules": [rule1, rule2, rule3, rule4, rule5, rule6, rule7],
    }

    # Set example lifecycle policy
    s3.put_bucket_lifecycle_configuration(
        Bucket=bucket_name, LifecycleConfiguration=lifecycle_policy
    )

    # Get new lifecycle configuration
    lifecycle_config = s3.get_bucket_lifecycle_configuration(
        Bucket=bucket_name,
    )

    if lifecycle_config["Rules"][0]["ID"] == rule_id:
        return {
            "message": "Successfully set example S3 lifecycle policy. Review and update as needed.",
            "status": "Success",
        }

    else:
        raise RuntimeError(
            f"Failed to set S3 lifecycle policy. Lifecycle rule ID did not match '{rule_id}'"
        )
