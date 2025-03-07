import json
import time

import boto3
from botocore.exceptions import ClientError

responses = {"EnableLogging": []}


def add_response(action, message, suppress=False):
    """Helper to create response objects."""
    return {"Action": action, "Suppress": suppress, "Message": message}


def add_error(action, error_msg):
    """Helper to create error response objects."""
    return {"Action": action, "Message": f"ERROR {error_msg}"}


def create_error_response(error_type, message):
    """Create standardized error response."""
    return {
        "output": "EnableLogging",
        "http_responses": {
            "EnableLogging": [{"Action": error_type, "Message": message}]
        },
    }


def createLogGroup(name, region, acct):
    """Create CloudWatch log group and return ARN."""
    result = []
    try:
        logs = boto3.client("logs", region_name=region)
        try:
            logs.create_log_group(logGroupName=name)
            result.append(add_response("create_log_group", f"Created log group {name}"))
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceAlreadyExistsException":
                result.append(
                    add_response("create_log_group", f"Log group {name} already exists")
                )
            else:
                raise

        arn = f"arn:aws:logs:{region}:{acct}:log-group:{name}"
        return arn, result
    except Exception as e:
        result.append(add_error("create_log_group", str(e)))
        return "", result


def runbook_handler(event, context):
    """Handles AWS Config remediation runbook for enabling logging."""

    # Validate required fields
    if "ResourceId" not in event:
        raise ValueError("Missing required input: ResourceId")

    if "ResourceType" not in event:
        raise ValueError("Missing required input: ResourceType")

    res_type = event["ResourceType"]

    if res_type == "AwsS3Bucket":
        res_id = event["ResourceId"]
        svc_name = "s3"
    else:
        res_id = event["ResourceId"]
        res_split = res_id.split(":")
        svc_name = res_split[2]

    res_type_map = {
        "elasticloadbalancing": "AwsElbv2LoadBalancer",
        "elb": "AwsElbv2LoadBalancer",
        "apigateway": "AwsApiGatewayStage",
        "execute-api": "AwsApiGatewayV2Stage",
        "states": "AwsStepFunctionsStateMachine",
        "cloudfront": "AwsCloudFrontDistribution",
        "s3": "AwsS3Bucket",
    }
    res_type = res_type_map.get(svc_name, "Unknown")

    if res_type == "Unknown":
        raise ValueError(f"Unknown resource type: {svc_name}")

    # Extract account ID
    if "AccountId" in event and event["AccountId"]:
        acct_id = event["AccountId"]
    else:
        try:
            acct_id = res_split[4]
            if not acct_id or not acct_id.isdigit():
                raise ValueError("Invalid account ID in resource ARN")
        except (IndexError, ValueError) as e:
            raise ValueError(f"Unable to extract valid account ID: {str(e)}")

    # Determine region
    if "Region" in event and event["Region"]:
        region = event["Region"]
    else:
        if svc_name == "cloudfront" or "AwsCloudFrontDistribution" in event.get(
            "ResourceType", ""
        ):
            region = "us-east-1"
        else:
            try:
                region = res_split[3] or "us-east-1"
            except (IndexError, TypeError):
                region = "us-east-1"

    # Convert elasticloadbalancing to elb for consistency
    if svc_name == "elasticloadbalancing":
        svc_name = "elb"

    logging_bucket = event["LoggingBucket"]

    # Log the extracted information
    responses["EnableLogging"].append(
        add_response("INFO", f"Using account ID: {acct_id} for resource: {res_id}")
    )
    responses["EnableLogging"].append(
        add_response("INFO", f"Using region: {region} for resource: {res_id}")
    )
    responses["EnableLogging"].append(
        add_response(
            "INFO", f"Using logging bucket: {logging_bucket} for resource: {res_id}"
        )
    )

    # Map resource types to handlers
    handlers = {
        "AwsElbv2LoadBalancer": lambda: handle_elbv2(res_id, region, svc_name, acct_id),
        "AwsApiGatewayStage": lambda: handle_api_gateway_stage(
            res_split, region, acct_id
        ),
        "AwsStepFunctionsStateMachine": lambda: handle_step_functions(
            res_split, res_id, region, acct_id
        ),
        "AwsApiGatewayV2Stage": lambda: handle_api_gateway_v2_stage(
            res_split, region, acct_id
        ),
        "AwsCloudFrontDistribution": lambda: handle_cloudfront_distribution(
            res_split, region, acct_id, logging_bucket
        ),
        "AwsS3Bucket": lambda: handle_s3_bucket(res_id, logging_bucket),
    }

    # Execute appropriate handler
    if res_type in handlers:
        responses["EnableLogging"].append(handlers[res_type]())
    else:
        responses["EnableLogging"].append(
            add_response(
                "ResourceTypeValidation", f"Unsupported resource type: {res_type}"
            )
        )

    # Overall we will assume that the overall status is not to be suppressed unless indicated
    # by the handler functions
    message = "Requested Generic Logging"
    for response in responses["EnableLogging"]:
        if "Message" in response:
            message = response["Message"]

    return {
        "status": "Success",
        "message": message,
        "details": responses,
    }


def handle_elbv2(res_id, region, svc, acct):
    """Configures logging for ELBv2 resources."""
    if (
        not res_id.startswith("arn:aws:elasticloadbalancing")
        or not region
        or svc != "elb"
        or not acct.isdigit()
    ):
        return add_error("validation", "Invalid parameters for ELBv2 logging")

    bucket = f"asr-logging-{svc}-{acct}-{region.lower()}"

    try:
        boto3.client("elbv2", region_name=region).modify_load_balancer_attributes(
            LoadBalancerArn=res_id,
            Attributes=[
                {"Key": "access_logs.s3.enabled", "Value": "true"},
                {"Key": "access_logs.s3.bucket", "Value": bucket},
            ],
        )
        return add_response("modify_lb_attrs", f"ELB {res_id} now logs to {bucket}")
    except ClientError as e:
        return add_error(
            "enable_logging",
            f"{e.response['Error']['Code']}: {e.response['Error']['Message']}",
        )
    except Exception as e:
        return add_error("enable_logging", f"Unexpected error: {str(e)}")
        raise RuntimeError(str(e))


def setupAPIGatewayAccountSettings(acct, client):
    """Sets up API Gateway account settings for CloudWatch logging."""
    result = []
    ROLE_NAME = "APIGatewayLogWriterRole"
    POLICY_ARN = (
        "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
    )
    ASSUME_ROLE = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": ["apigateway.amazonaws.com"]},
                "Action": ["sts:AssumeRole"],
            }
        ],
    }

    if "cloudwatchRoleArn" not in client.get_account():
        iam = boto3.client("iam")
        try:
            iam.create_role(
                RoleName=ROLE_NAME,
                AssumeRolePolicyDocument=json.dumps(ASSUME_ROLE),
                Description="Role for API Gateway CloudWatch Logs",
            )
            result.append(add_response("create_role", f"Role {ROLE_NAME} created"))
        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityAlreadyExists":
                result.append(add_response("create_role", f"Role {ROLE_NAME} exists"))
            else:
                return [add_error("create_role", e.response["Error"]["Message"])]

        try:
            iam.attach_role_policy(RoleName=ROLE_NAME, PolicyArn=POLICY_ARN)
            result.append(
                add_response("attach_policy", f"Policy attached to {ROLE_NAME}")
            )
        except ClientError as e:
            return [add_error("attach_policy", e.response["Error"]["Message"])]

        try:
            role_arn = f"arn:aws:iam::{acct}:role/{ROLE_NAME}"
            client.update_account(
                patchOperations=[
                    {"op": "replace", "path": "/cloudwatchRoleArn", "value": role_arn}
                ]
            )
            result.append(add_response("update_account", "Set cloudwatchRoleArn"))
        except ClientError as e:
            result.append(add_error("update_account", e.response["Error"]["Message"]))

    return result


def handle_api_gateway_stage(res_split, region, acct):
    """Configure logging for API Gateway stage."""
    result = []
    LOG_LEVEL = "ERROR"
    LOG_PREFIX = "/aws/vendedlogs/APIGW-Access_"
    LOG_FORMAT = """{"requestId":"$context.requestId","ip":"$context.identity.sourceIp","caller":"$context.identity.caller","user":"$context.identity.user","requestTime":"$context.requestTime","httpMethod":"$context.httpMethod","resourcePath":"$context.resourcePath","status":"$context.status","protocol":"$context.protocol","responseLength":"$context.responseLength"}"""

    try:
        client = boto3.client("apigateway", region_name=region)
        api_parts = res_split[5].split("/")
        api_id = api_parts[2]
        stage = api_parts[4]

        # Setup account settings
        result.extend(setupAPIGatewayAccountSettings(acct, client))

        # Create log group
        log_group_arn, create_results = createLogGroup(
            f"{LOG_PREFIX}{api_id}/{stage}", region, acct
        )
        result.extend(create_results)

        # Get stage info
        try:
            response = client.get_stage(restApiId=api_id, stageName=stage)
        except ClientError as e:
            return add_error("get_stage", e.response["Error"]["Message"])

        # Check what needs updating
        patches = []

        # Access logging
        if not response.get("accessLogSettings", {}).get("destinationArn", ""):
            patches.extend(
                [
                    {
                        "op": "replace",
                        "path": "/accessLogSettings/destinationArn",
                        "value": log_group_arn,
                    },
                    {
                        "op": "replace",
                        "path": "/accessLogSettings/format",
                        "value": LOG_FORMAT,
                    },
                ]
            )

        # Tracing
        if not response.get("tracingEnabled", False):
            patches.append(
                {"op": "replace", "path": "/tracingEnabled", "value": "true"}
            )

        # Method logging
        if (
            response.get("methodSettings", {}).get("*/*", {}).get("loggingLevel", "OFF")
            == "OFF"
        ):
            patches.append(
                {"op": "replace", "path": "/*/*/logging/loglevel", "value": LOG_LEVEL}
            )

        # Apply patches
        if patches:
            try:
                client.update_stage(
                    restApiId=api_id, stageName=stage, patchOperations=patches
                )
                result.append(
                    add_response("update_stage", f"API {api_id} Stage {stage} updated")
                )
            except Exception as e:
                result.append(add_error("update_stage", str(e)))
        else:
            result.append(
                add_response("patch", "No changes needed - already compliant")
            )

    except Exception as e:
        result.append(
            add_error("update_stage", f"Failed to configure API Gateway: {str(e)}")
        )

    return result[0] if result else add_error("unknown", "No result generated")


def handle_step_functions(res_split, res_id, region, acct):
    """Configure logging for Step Functions state machine."""
    result = []

    try:
        sfn = boto3.client("stepfunctions", region_name=region)
        sfn_name = res_split[6]

        # Get state machine config
        try:
            response = sfn.describe_state_machine(stateMachineArn=res_id)
            role_arn = response["roleArn"]
            log_group_arn = ""

            # Check existing logging
            if "loggingConfiguration" in response:
                cfg = response["loggingConfiguration"]
                if "destinations" in cfg and cfg["destinations"]:
                    dest = cfg["destinations"][0]
                    if "cloudWatchLogsLogGroup" in dest:
                        log_group = dest["cloudWatchLogsLogGroup"]
                        log_group_arn = log_group.get("logGroupArn", "")
        except ClientError as e:
            return add_error("describe_machine", e.response["Error"]["Message"])

        # Extract role name
        role_name = role_arn.split("/")[1]

        # Create log group if needed
        if not log_group_arn:
            log_group_arn, create_results = createLogGroup(
                f"/aws/SFNLog/{sfn_name}", region, acct
            )
            log_group_arn = f"{log_group_arn}:*"
            result.extend(create_results)

        # Update role permissions
        iam = boto3.client("iam")
        try:
            iam.attach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
            )
        except ClientError:
            pass  # Policy might already be attached

        # Wait for IAM propagation
        time.sleep(10)

        # Update state machine logging
        try:
            sfn.update_state_machine(
                stateMachineArn=res_id,
                loggingConfiguration={
                    "level": "ERROR",
                    "includeExecutionData": False,
                    "destinations": [
                        {"cloudWatchLogsLogGroup": {"logGroupArn": log_group_arn}},
                    ],
                },
            )
            result.append(
                add_response(
                    "update_machine", f"Step function {sfn_name} logging enabled"
                )
            )
        except ClientError as e:
            result.append(add_error("update_machine", e.response["Error"]["Message"]))

    except Exception as e:
        result.append(add_error("enable_logging", str(e)))

    return result[0] if result else add_error("unknown", "No result generated")


def handle_api_gateway_v2_stage(res_split, region, acct):
    """Configure logging for API Gateway V2 stage."""
    result = []

    try:
        v2_client = boto3.client("apigatewayv2", region_name=region)
        v1_client = boto3.client("apigateway", region_name=region)

        # Parse API ID and stage
        api_parts = res_split[5].split("/")
        api_id = api_parts[2]
        stage = api_parts[4]

        # Setup account settings
        result.extend(setupAPIGatewayAccountSettings(acct, v1_client))

        # Create log group
        log_group_arn, create_results = createLogGroup(
            f"/aws/vendedlogs/APIGW-Access_{api_id}/{stage}", region, acct
        )
        result.extend(create_results)

        # Get API details
        try:
            api_response = v2_client.get_api(ApiId=api_id)
            protocol = api_response["ProtocolType"]
            if protocol not in ["HTTP", "WEBSOCKET"]:
                return add_error(
                    "validate_protocol", f"Invalid Protocol type: {protocol}"
                )
        except ClientError as e:
            return add_error("get_api", e.response["Error"]["Message"])

        # Get stage config
        try:
            stage_response = v2_client.get_stage(ApiId=api_id, StageName=stage)
        except ClientError as e:
            return add_error("get_stage", e.response["Error"]["Message"])

        # Check what needs updating
        updates = {"ApiId": api_id, "StageName": stage}

        # Access logging
        if not stage_response.get("AccessLogSettings", {}).get("DestinationArn"):
            updates["AccessLogSettings"] = {
                "DestinationArn": log_group_arn,
                "Format": json.dumps(
                    {
                        "requestId": "$context.requestId",
                        "ip": "$context.identity.sourceIp",
                        "caller": "$context.identity.caller",
                        "user": "$context.identity.user",
                        "requestTime": "$context.requestTime",
                        "httpMethod": "$context.httpMethod",
                        "resourcePath": "$context.resourcePath",
                        "status": "$context.status",
                        "protocol": "$context.protocol",
                        "responseLength": "$context.responseLength",
                    }
                ),
            }

        # WebSocket logging
        if (
            protocol == "WEBSOCKET"
            and stage_response.get("DefaultRouteSettings", {}).get("LoggingLevel")
            == "OFF"
        ):
            updates["DefaultRouteSettings"] = {"LoggingLevel": "ERROR"}

        # Apply updates if needed
        if len(updates) > 2:  # More than just ApiId and StageName
            try:
                v2_client.update_stage(**updates)
                result.append(
                    add_response("update_stage", f"API {api_id} Stage {stage} updated")
                )
            except ClientError as e:
                result.append(add_error("update_stage", e.response["Error"]["Message"]))
        else:
            result.append(
                add_response("patch", "No changes needed - already compliant")
            )

    except Exception as e:
        result.append(add_error("update_stage", str(e)))

    return result[0] if result else add_error("unknown", "No result generated")


def handle_cloudfront_distribution(res_split, region, acct, logging_bucket):
    """Configure CloudFront distribution for logging and security best practices."""
    result = []

    dist_parts = res_split[5].split("/")
    dist_id = dist_parts[1]

    # Get distribution config
    cf = boto3.client("cloudfront")
    try:
        response = cf.get_distribution(Id=dist_id)
        if response["Distribution"]["Status"] != "Deployed":
            return add_error(
                "get_distribution",
                f"Cannot update when status is {response['Distribution']['Status']}",
            )

        etag = response["ETag"]
        dist = response["Distribution"]
        cfg = dist["DistributionConfig"]

        # Track changes
        changes_made = False

        # Default root object
        if not cfg.get("DefaultRootObject"):
            cfg["DefaultRootObject"] = "index.html"
            changes_made = True
            result.append(
                add_response(
                    "set_default_root", "Updated DefaultRootObject to 'index.html'"
                )
            )

        # Viewer protocol policy
        if cfg["DefaultCacheBehavior"]["ViewerProtocolPolicy"] == "allow-all":
            cfg["DefaultCacheBehavior"]["ViewerProtocolPolicy"] = "redirect-to-https"
            changes_made = True
            result.append(
                add_response("update_protocol", "Updated to redirect-to-https")
            )

        # TLS settings
        if cfg.get("Aliases", {}).get("Quantity", 0) > 0:
            try:
                cert = cfg["ViewerCertificate"]
                if cert.get("MinimumProtocolVersion") != "TLSv1.2_2021":
                    cert["MinimumProtocolVersion"] = "TLSv1.2_2021"
                    changes_made = True
                    result.append(add_response("update_tls", "Updated to TLSv1.2_2021"))
            except KeyError:
                pass

        # HTTP version
        if cfg.get("HttpVersion", "http1.1") != "http2and3":
            cfg["HttpVersion"] = "http2and3"
            changes_made = True
            result.append(add_response("update_http", "Updated to HTTP/2 and HTTP/3"))

        # Add comment if missing
        if not cfg.get("Comment"):
            cfg["Comment"] = (
                "FIXME - You should really have a description for what this cloudfront does!"
            )
            changes_made = True
            result.append(add_response("add_comment", "Added default comment"))

        # Enable logging
        if not cfg.get("Logging", {}).get("Enabled", False):
            cfg["Logging"] = {
                "Enabled": True,
                "IncludeCookies": True,
                "Bucket": f"{logging_bucket}.s3.amazonaws.com",
                "Prefix": f"{acct}/",
            }
            changes_made = True
            result.append(
                add_response("enable_logging", f"Enabled logging to {logging_bucket}")
            )

        # Apply changes if needed
        if changes_made:
            try:
                cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
                result.append(
                    add_response(
                        "update_distribution", f"Distribution {dist_id} updated"
                    )
                )
            except ClientError as e:
                return add_error(
                    "update_distribution",
                    f"{e.response['Error']['Code']}: {e.response['Error']['Message']}",
                )
        else:
            result.append(
                add_response(
                    "check_distribution", "No changes needed - already compliant"
                )
            )

    except ClientError as e:
        return add_error(
            "cloudfront_operation",
            f"{e.response['Error']['Code']}: {e.response['Error']['Message']}",
        )
    except Exception as e:
        return add_error("cloudfront_operation", str(e))

    return result[0] if result else add_error("unknown", "No result generated")


def handle_s3_bucket(bucket_name, logging_bucket):
    result = []
    # bucket_name is the resource name
    s3_client = boto3.client("s3")
    target_prefix = f"{bucket_name}/"

    try:
        # Check for circular recursive logging scenarios
        if bucket_name == logging_bucket:
            return add_response(
                "server_access_logging",
                f"same_bucket_check: {bucket_name} is a logging bucket and cannot log to itself!",
                True,  # Flag the suppression request
            )

        # Get tags of the source bucket
        try:
            response = s3_client.get_bucket_tagging(Bucket=bucket_name)
            tags = response.get("TagSet", [])
            # Look for a tag of exemptLoggingBucket=True
            for tag in tags:
                if tag["Key"] == "exemptLoggingBucket" and tag["Value"] == "True":
                    return add_response(
                        "server_access_logging",
                        f"exemptLoggingBucket_check: {bucket_name} is exempt from logging!",
                        True,  # Flag the suppression request
                    )
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchTagSet":
                # No tags on the bucket, continue with logging setup
                pass
            else:
                # Re-raise other ClientError exceptions
                raise

        # Check if source bucket exists
        s3_client.head_bucket(Bucket=bucket_name)

        # Check if destination bucket exists
        s3_client.head_bucket(Bucket=logging_bucket)

        # Enable access logging
        s3_client.put_bucket_logging(
            Bucket=bucket_name,
            BucketLoggingStatus={
                "LoggingEnabled": {
                    "TargetBucket": logging_bucket,
                    "TargetPrefix": target_prefix,
                    "TargetObjectKeyFormat": {
                        "PartitionedPrefix": {"PartitionDateSource": "EventTime"}
                    },
                }
            },
        )

        result.append(
            add_response(
                "server_access_logging",
                f"Bucket {bucket_name} is logging to {logging_bucket}",
            )
        )
    except s3_client.exceptions.NoSuchBucket:
        return add_error(
            "server_access_logging",
            f"bucket_exists_check: {bucket_name} or {logging_bucket} doesnt exist!",
        )
    except Exception as e:
        return add_error(
            "server_access_logging",
            f"{e.response['Error']['Code']}: {bucket_name} or {logging_bucket} doesnt exist!",
        )

    return result[0] if result else add_error("unknown", "No result generated")


# For local testing
if __name__ == "__main__":
    # Example event for testing
    test_event = {
        "ResourceId": "cnxc-s3-server-access-logging-211125410042-us-east-1",
        "Region": "us-east-1",
        "AccountId": "211125410042",
        "ResourceType": "AwsS3Bucket",
        "LoggingBucket": "cnxc-s3-server-access-logging-211125410042-us-east-1",
    }
    print(json.dumps(runbook_handler((test_event), None), indent=4))
