# import dis
# import json
import time
from typing import Dict, List, Literal, TypedDict

import boto3  # type: ignore
from botocore.exceptions import ClientError  # type: ignore


class Response(TypedDict):
    Action: str
    Message: str


responses: Dict[Literal["EnableLogging"], List[Response]] = {}
responses["EnableLogging"] = []


def runbook_handler(event, context):
    ResourceId = event["ResourceId"]
    ResourceSplit = ResourceId.split(":")
    serviceName = ResourceSplit[2]
    if serviceName == "elasticloadbalancing":
        serviceName = "elb"
    region = event["Region"]
    AwsAccountId = event["AccountId"]
    ResourceType = event["ResourceType"]

    loggingBucket = (
        "asr-logging-" + serviceName + "-" + AwsAccountId + "-" + region.lower()
    )

    responses["EnableLogging"].append(
        {
            "Action": "determine_logging_bucket",
            "Message": f"Logging bucket will be {loggingBucket}",
        }
    )

    if ResourceType == "AwsElbv2LoadBalancer":
        client = boto3.client("elbv2", region_name=region)
        try:
            client.modify_load_balancer_attributes(
                LoadBalancerArn=ResourceId,
                Attributes=[
                    {"Key": "access_logs.s3.enabled", "Value": "true"},
                    {"Key": "access_logs.s3.bucket", "Value": loggingBucket},
                ],
            )
            responses["EnableLogging"].append(
                {
                    "Action": "modify_load_balancer_attributes",
                    "Message": f"ELB Resource {ResourceId} Modified for logging to {loggingBucket}",
                }
            )

        except Exception as error:
            responses["EnableLogging"].append(
                {
                    "Action": "enable_logging",
                    "Message": f"ERROR Unable to set logging on AwsElbv2LoadBalancer - {error.response['Error']['Code']}",
                }
            )
            pass

    if ResourceType == "AwsApiGatewayStage":
        try:
            # Use V2 for Websocket and V1 for Rest
            apigwclient = boto3.client("apigateway", region_name=region)
            apigwArray = ResourceSplit[5].split("/")
            ApiId = apigwArray[2]
            stageName = apigwArray[4]

            # Make sure API Gateway Account level settings have Cloudwatch Role
            setupAPIGatewayAccountSettings(AwsAccountId, apigwclient)

            # Get/Create Log Group for access and execution logging
            accesslogGroupArn = createLogGroup(
                "/aws/vendedlogs/APIGW-Access_" + ApiId + "/" + stageName,
                region,
                AwsAccountId,
            )
            # executelogGroupArn = createLogGroup('/aws/apigateway/execution/'+ApiId+'/'+stageName, region, AwsAccountId)

            # Get the current Stage Info and figure out whats needed
            response = apigwclient.get_stage(restApiId=ApiId, stageName=stageName)

            # Access Logging required?
            try:
                accessLogSettings = response["accessLogSettings"]["destinationArn"]
                if accessLogSettings != "":
                    setAccessLogging = False
                else:
                    setAccessLogging = True
            except Exception:
                setAccessLogging = True
                pass

            # Execute Logging Required?
            try:
                methodSettings = response["methodSettings"]["*/*"]["loggingLevel"]
                if methodSettings == "OFF":
                    setMethodLogging = True
                else:
                    setMethodLogging = False
            except Exception:
                setMethodLogging = True
                pass

            # XRay Tracing Required?
            try:
                xray = response["tracingEnabled"]
                if xray is False:
                    setXray = True
                else:
                    setXray = False
            except Exception:
                setXray = True
                pass

            # Build up an array of items to patch
            PatchOperations = []
            if setAccessLogging:
                operation = {
                    "op": "replace",
                    "path": "/accessLogSettings/destinationArn",
                    "value": accesslogGroupArn,
                    # 'from': 'string'
                }
                PatchOperations.append(operation)
                operation = {
                    "op": "replace",
                    "path": "/accessLogSettings/format",
                    "value": '{ "requestId":"$context.requestId", "ip": "$context.identity.sourceIp", \
                                "caller":"$context.identity.caller", "user":"$context.identity.user", \
                                "requestTime":"$context.requestTime", \
                                "httpMethod":"$context.httpMethod","resourcePath":"$context.resourcePath", \
                                "status":"$context.status","protocol":"$context.protocol", \
                                "responseLength":"$context.responseLength" }',
                }
                PatchOperations.append(operation)
            if setXray:
                operation = {
                    "op": "replace",
                    "path": "/tracingEnabled",
                    "value": "true",
                }
                PatchOperations.append(operation)
            if setMethodLogging:
                operation = {
                    "op": "replace",
                    "path": "/*/*/logging/loglevel",
                    "value": "ERROR",
                }
                PatchOperations.append(operation)

            # If there are items to patch, then patch them!
            if len(PatchOperations) > 0:
                try:
                    apigwclient.update_stage(
                        restApiId=ApiId,
                        stageName=stageName,
                        patchOperations=PatchOperations,
                    )
                    responses["EnableLogging"].append(
                        {
                            "Action": "update_stage",
                            "Message": f"API ID {ApiId} Stage {stageName} updated",
                        }
                    )
                except Exception as error:
                    responses["EnableLogging"].append(
                        {
                            "Action": "update_stage",
                            "Message": f"ERROR - API ID {ApiId} Stage {stageName} not updated {error.response['Error']['Code']}",
                        }
                    )
                    pass
            else:
                responses["EnableLogging"].append(
                    {
                        "Action": "patch",
                        "Message": "No Patch operations required for APIGateway - Why was remediation requested?",
                    }
                )

        except Exception as error:
            responses["EnableLogging"].append(
                {
                    "Action": "enable_logging",
                    "Message": f"ERROR Unable to set logging on AwsApiGatewayStage - {error.response['Error']['Code']}",
                }
            )
            pass

    if ResourceType == "AwsStepFunctionsStateMachine":
        try:
            sfnclient = boto3.client("stepfunctions", region_name=region)

            # arn:aws:states:us-east-1:529247589681:stateMachine:XPVA-SDN248-SHD-COMM-RetentionStateMachine
            sfnName = ResourceSplit[6]

            # Get the state machine info
            response = sfnclient.describe_state_machine(stateMachineArn=ResourceId)
            roleArn = response["roleArn"]
            # logLevel = "OFF"
            logGroupArn = ""

            # a lot of crap just to get overrides
            if "loggingConfiguration" in response:
                loggingConfiguration = response["loggingConfiguration"]
                # logLevel = loggingConfiguration["level"]
                if "destinations" in loggingConfiguration:
                    destinations = loggingConfiguration["destinations"]
                    destination = destinations[0]  # limited to one
                    if "cloudWatchLogsLogGroup" in destination:
                        cloudWatchLogsLogGroup = destination["cloudWatchLogsLogGroup"]
                        if "logGroupArn" in cloudWatchLogsLogGroup:
                            logGroupArn = cloudWatchLogsLogGroup["logGroupArn"]

            roleArray = roleArn.split("/")
            roleName = roleArray[1]

            if logGroupArn == "":
                # Get/Create Log Group for access and execution logging
                logGroupArn = (
                    createLogGroup("/aws/SFNLog/" + sfnName, region, AwsAccountId)
                    + ":*"
                )

            print(
                f"[INFO] Role {roleName} will be updated for cloudwatch logs permissions"
            )
            print(f"[INFO] StepFunction {sfnName} will be logged to {logGroupArn}")

            # Attach Permission to Role
            iamClient = boto3.client("iam")

            try:
                iamClient.attach_role_policy(
                    RoleName=roleName,
                    PolicyArn="arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
                )
            except Exception as e:
                print(e)
                pass
            print(f"[INFO] Role {roleName} updated for CloudWatchLogsFullAccess")
            print(
                "[INFO] Delay 10 seconds waiting for role consistency because no waiter available"
            )
            time.sleep(10)  # Sleep for 10 seconds

            # update the state machine
            response = sfnclient.update_state_machine(
                stateMachineArn=ResourceId,
                loggingConfiguration={
                    "level": "ERROR",
                    "includeExecutionData": False,
                    "destinations": [
                        {"cloudWatchLogsLogGroup": {"logGroupArn": logGroupArn}},
                    ],
                },
            )
            responses["EnableLogging"].append(
                {
                    "Action": "update_state_machine",
                    "Message": f"Step function {sfnName} modified for logging",
                }
            )
        except Exception as error:
            responses["EnableLogging"].append(
                {
                    "Action": "enable_logging",
                    "Message": f"ERROR Unable to set logging on AwsStepFunctionsStateMachine - {error.response['Error']['Code']}",
                }
            )
            pass

    if ResourceType == "AwsApiGatewayV2Stage":
        try:
            apigwclientv2 = boto3.client("apigatewayv2", region_name=region)
            apigwclientv1 = boto3.client("apigateway", region_name=region)
            apigwArray = ResourceSplit[5].split("/")
            ApiId = apigwArray[2]
            stageName = apigwArray[4]

            # Make sure API Gateway Account level settings have Cloudwatch Role
            # uses v1 settings for account level
            setupAPIGatewayAccountSettings(AwsAccountId, apigwclientv1)

            # Get/Create Log Group for access and execution logging
            # accesslogGroupArn = createLogGroup('API-Gateway-Access-Logs_'+ApiId+'/'+stageName, region, AwsAccountId)
            accesslogGroupArn = createLogGroup(
                "/aws/vendedlogs/APIGW-Access_" + ApiId + "/" + stageName,
                region,
                AwsAccountId,
            )

            # Get some info on the API
            response = apigwclientv2.get_api(ApiId=ApiId)
            ProtocolType = response["ProtocolType"]
            if ProtocolType != "HTTP" and ProtocolType != "WEBSOCKET":
                exit(f"Invalid Protocol type on API [{ProtocolType}]")

            # Get the current Stage Info and figure out whats needed
            response = apigwclientv2.get_stage(
                ApiId=ApiId, StageName=stageName
            )  # Params differ v1 to v2

            # Access Logging required?
            setAccessLogging = True
            if "AccessLogSettings" in response:
                if "DestinationArn" in response["AccessLogSettings"]:
                    accessLogSettings = response["AccessLogSettings"]["DestinationArn"]
                    if accessLogSettings != "":
                        setAccessLogging = False

            # Execute Logging Required?
            try:
                methodSettings = response["DefaultRouteSettings"]["LoggingLevel"]
                if methodSettings == "OFF":
                    setMethodLogging = True
                else:
                    setMethodLogging = False
            except Exception:
                setMethodLogging = True
                pass

            # XRay Tracing Required?
            setXray = False

            # Build up an array of items to patch
            PatchOperations = {}
            if setAccessLogging:
                operation = {}
                operation["DestinationArn"] = accesslogGroupArn
                operation["Format"] = (
                    '{ "requestId":"$context.requestId", "ip": "$context.identity.sourceIp", \
                        "caller":"$context.identity.caller", "user":"$context.identity.user",\
                        "requestTime":"$context.requestTime", "httpMethod":"$context.httpMethod",\
                        "resourcePath":"$context.resourcePath", "status":"$context.status",\
                        "protocol":"$context.protocol", "responseLength":"$context.responseLength" }'
                )
                PatchOperations["AccessLogSettings"] = operation

            if setMethodLogging and ProtocolType == "WEBSOCKET":
                operation = {}
                operation["LoggingLevel"] = "ERROR"
                PatchOperations["DefaultRouteSettings"] = operation

            # If there are items to patch, then patch them!
            if len(PatchOperations) > 0:
                PatchOperations["ApiId"] = ApiId
                PatchOperations["StageName"] = stageName

                print(
                    f"[INFO] The following Patch operations to the stage {stageName} will occur"
                )
                print(PatchOperations)

                try:
                    apigwclientv2.update_stage(**PatchOperations)
                except Exception as error:
                    responses["EnableLogging"].append(
                        {
                            "Action": "update_stage",
                            "Message": f"ERROR API {ApiId} Stage {stageName} NOT patched - {error.response['Error']['Code']}",
                        }
                    )
                    pass
            else:
                responses["EnableLogging"].append(
                    {
                        "Action": "patch",
                        "Message": "ERROR No Patch operations required for APIGateway - Why was remediation requested?",
                    }
                )

        except Exception as error:
            responses["EnableLogging"].append(
                {
                    "Action": "update_stage",
                    "Message": f"ERROR Unable to set logging on AwsApiGatewayV2Stage - {error.response['Error']['Code']}",
                }
            )
            pass

    if ResourceType == "AwsCloudFrontDistribution":
        # DEBUG = False

        distributionSplit = ResourceSplit[5].split("/")
        distributionId = distributionSplit[1]

        # Get the current Distribution Config
        # To update a web distribution using the CloudFront API
        #   Use GetDistributionConfig to get the current configuration, including the version identifier ( ETag).
        #   Update the distribution configuration that was returned in the response. Note the following important requirements and restrictions:
        #   You must rename the ETag field to IfMatch, leaving the value unchanged. (Set the value of IfMatch to the value of ETag, then remove the ETag field.)
        #   You can’t change the value of CallerReference.
        #   Submit an UpdateDistribution request, providing the distribution configuration. The new configuration replaces the existing configuration. The values that
        #   you specify in an UpdateDistribution request are not merged into your existing configuration. Make sure to include all fields: the ones that you modified
        #   and also the ones that you didn’t.

        # Permissions required:
        # remediationPolicy2.addActions('cloudfront:GetDistribution*', 'cloudfront:UpdateDistribution');

        cloudfrontClient = boto3.client("cloudfront")
        response = cloudfrontClient.get_distribution(Id=distributionId)
        responses["EnableLogging"].append(
            {
                "Action": "get_distribution",
                "Message": f"Distribution {distributionId} currently has a status of {response['Distribution']['Status']}",
            }
        )
        if response["Distribution"]["Status"] != "Deployed":
            responses["EnableLogging"].append(
                {
                    "Action": "get_distribution",
                    "Message": f"cannot update cloudfront config when its status is {response['Distribution']['Status']}",
                }
            )
            exit(
                f"cannot update cloudfront config when its status is {response['Distribution']['Status']}"
            )
        else:
            ETag = response["ETag"]  # Save the Etag
            response.pop("ETag")  # Remove the Etag

            parameters = {}

            distribution = response["Distribution"]
            DistributionConfig = distribution["DistributionConfig"]

            parameters["IfMatch"] = ETag  # Save the Etag as IfMatch

            # Need to update the DefaultRootObject to index.html?
            updateDefaultRoot = True

            if "DefaultRootObject" in DistributionConfig:
                if DistributionConfig["DefaultRootObject"] != "":
                    updateDefaultRoot = False
            else:
                print(DistributionConfig)
                exit("No DistributionConfig in response!!!")

            if updateDefaultRoot:
                DistributionConfig["DefaultRootObject"] = "index.html"
                responses["EnableLogging"].append(
                    {
                        "Action": "set_default_root_object",
                        "Message": "Updating DefaultRootObject from None to 'index.html'",
                    }
                )
            else:
                responses["EnableLogging"].append(
                    {
                        "Action": "set_default_root_object",
                        "Message": f"DefaultRootObject remains as {DistributionConfig['DefaultRootObject']}",
                    }
                )

            ViewerProtocolPolicy = DistributionConfig["DefaultCacheBehavior"][
                "ViewerProtocolPolicy"
            ]
            if ViewerProtocolPolicy == "allow-all":
                responses["EnableLogging"].append(
                    {
                        "Action": "update_viewer_protocol_policy",
                        "Message": "Updating ViewerProtocolPolicy from 'allow-all' to 'redirect-to-https' for better 'security'",
                    }
                )
                DistributionConfig["DefaultCacheBehavior"][
                    "ViewerProtocolPolicy"
                ] = "redirect-to-https"
            else:
                responses["EnableLogging"].append(
                    {
                        "Action": "update_viewer_protocol_policy",
                        "Message": f"ViewerProtocolPolicy of '{ViewerProtocolPolicy}' meets security requirement for https",
                    }
                )

            # Using SNI?
            if DistributionConfig["Aliases"]["Quantity"] > 0:
                ViewerCert = DistributionConfig["ViewerCertificate"]
                SSLSupportMethod = ViewerCert["SSLSupportMethod"]
                MinimumProtocolVersion = ViewerCert["MinimumProtocolVersion"]
                DesiredProtocolVersion = "TLSv1.2_2021"
                if SSLSupportMethod != "sni-only":
                    responses["EnableLogging"].append(
                        {
                            "Action": "check_ssl_support_method",
                            "Message": f"[ERROR] CLOUDFRONT CONFIGURED WITH A NON STANDARD EXPENSIVE OPTION  (SSLSupportMethod={SSLSupportMethod})",
                        }
                    )
                if MinimumProtocolVersion != DesiredProtocolVersion:
                    responses["EnableLogging"].append(
                        {
                            "Action": "check_minimum_protocol_version",
                            "Message": f"Updating Cloudfront viewer certificate, minimum security protocol requirement from {MinimumProtocolVersion} to {DesiredProtocolVersion}",
                        }
                    )
                    DistributionConfig["ViewerCertificate"][
                        "MinimumProtocolVersion"
                    ] = DesiredProtocolVersion
            else:
                responses["EnableLogging"].append(
                    {
                        "Action": "check_distro_aliases",
                        "Message": "WARNING - You are not supposed to use the default domain name;  Please update to use a custom domain name (SNI)",
                    }
                )

            # http version http/2 and http/3
            if DistributionConfig["HttpVersion"] != "http2and3":
                responses["EnableLogging"].append(
                    {
                        "Action": "check_http_version",
                        "Message": "Updating DistributionConfig HttpVersion to http2and3",
                    }
                )
                DistributionConfig["HttpVersion"] = "http2and3"

            if DistributionConfig["Comment"] == "":
                DistributionConfig["Comment"] = (
                    "FIXME - You should really have a description for what this cloudfront does!"
                )

            if DistributionConfig["Logging"]["Enabled"] is False:
                DistributionConfig["Logging"]["Enabled"] = True
                DistributionConfig["Logging"]["IncludeCookies"] = True
                DistributionConfig["Logging"]["Bucket"] = (
                    event["LoggingBucket"] + ".s3.amazonaws.com"
                )
                DistributionConfig["Logging"]["Prefix"] = AwsAccountId + "/"
                responses["EnableLogging"].append(
                    {
                        "Action": "set_logging",
                        "Message": f"Set logging to bucket to {event['LoggingBucket']}",
                    }
                )

            parameters["DistributionConfig"] = DistributionConfig

            if "Id" not in parameters:
                parameters["Id"] = distributionId

            # Prettyprint the parameters
            # print(json.dumps(parameters, indent=4))
            # exit()

            try:
                response = cloudfrontClient.update_distribution(**parameters)
                responses["EnableLogging"].append(
                    {
                        "Action": "update_distribution",
                        "Message": f"Logging set on AwsCloudFrontDistribution {distributionId}",
                    }
                )
            except Exception as error:
                responses["EnableLogging"].append(
                    {
                        "Action": "update_distribution",
                        "Message": f"ERROR Unable to set logging on AwsCloudFrontDistribution - {error.response['Error']['Code']}",
                    }
                )
                pass

    return {"output": "EnableLogging", "http_responses": responses}


def setupAPIGatewayAccountSettings(AwsAccountId, apigwclient):
    response = apigwclient.get_account()
    if "cloudwatchRoleArn" not in response:
        # Create a cloudwatch role and assign it to account
        iamClient = boto3.client("iam")
        roleName = "APIGatewayLogWriterRole"
        try:
            iamClient.create_role(
                RoleName=roleName,
                AssumeRolePolicyDocument='{"Version": "2012-10-17","Statement": [{"Sid": "","Effect": "Allow","Principal": {"Service": ["apigateway.amazonaws.com"]},"Action": ["sts:AssumeRole"]}]}',
                Description="A role which allows API Gateway to write to CloudWatch Logs",
            )
            responses["EnableLogging"].append(
                {
                    "Action": "create_role",
                    "Message": f"Role {roleName} created for API Gateway Cloudwatch Logs",
                }
            )

        except ClientError as error:
            # Put your error handling logic here
            if error.response["Error"]["Code"] == "EntityAlreadyExists":
                responses["EnableLogging"].append(
                    {
                        "Action": "create_role",
                        "Message": f"Role {roleName} already exists for API Gateway Cloudwatch Logs",
                    }
                )
            else:
                responses["EnableLogging"].append(
                    {
                        "Action": "create_role",
                        "Message": f"ERROR Role {roleName} {error.response['Error']['Code']}",
                    }
                )
                pass

        # Attach Permission to Role
        try:
            iamClient.attach_role_policy(
                RoleName=roleName,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs",
            )
            responses["EnableLogging"].append(
                {
                    "Action": "attach_role_policy",
                    "Message": f"Role {roleName} now has policy AmazonAPIGatewayPushToCloudWatchLogs",
                }
            )
        except Exception as error:
            responses["EnableLogging"].append(
                {
                    "Action": "attach_role_policy",
                    "Message": f"ERROR Role {roleName} policy AmazonAPIGatewayPushToCloudWatchLogs -{error.response['Error']['Code']}",
                }
            )
            pass

        try:
            response = apigwclient.update_account(
                patchOperations=[
                    {
                        "op": "replace",
                        "path": "/cloudwatchRoleArn",
                        "value": f"arn:aws:iam::{AwsAccountId}:role/APIGatewayLogWriterRole",
                    },
                ]
            )
            responses["EnableLogging"].append(
                {
                    "Action": "update_account",
                    "Message": f"Set cloudwatchRoleArn to arn:aws:iam::{AwsAccountId}:role/APIGatewayLogWriterRole",
                }
            )
        except Exception as error:
            responses["EnableLogging"].append(
                {
                    "Action": "update_account",
                    "Message": f"ERROR Set cloudwatchRoleArn to arn:aws:iam::{AwsAccountId}:role/APIGatewayLogWriterRole -{error.response['Error']['Code']}",
                }
            )
            pass
    else:
        print(
            "[INFO] Cloudwatch Role already exists for API Gateway Account Settings... skipping Role Creation"
        )
        responses["EnableLogging"].append(
            {
                "Action": "set_cloudwatch_rolet",
                "Message": "Cloudwatch Role already exists for API Gateway Account Settings... skipping Role Creation",
            }
        )
    return


def createLogGroup(logGroupName, region, AwsAccountId):
    logGroupName = logGroupName.replace("$default", "dollar_default")
    try:
        logsclient = boto3.client("logs", region_name=region)
        response = logsclient.create_log_group(
            logGroupName=logGroupName, tags={"CreatedBy": "ASR-Remediation"}
        )
        responses["EnableLogging"].append(
            {
                "Action": "create_log_group",
                "Message": f"Create Log Group {logGroupName}",
            }
        )
    except ClientError as error:
        # Put your error handling logic here
        # print(error.response['Error']['Code'])
        if error.response["Error"]["Code"] == "ResourceAlreadyExistsException":
            responses["EnableLogging"].append(
                {
                    "Action": "create_log_group",
                    "Message": f"Log Group {logGroupName} already exists... proceeding",
                }
            )
        else:
            responses["EnableLogging"].append(
                {
                    "Action": "create_log_group",
                    "Message": f"ERROR Log Group {logGroupName} - {error.response['Error']['Code']}",
                }
            )
        pass

    # Get log Group Info
    response = logsclient.describe_log_groups(
        logGroupNamePrefix=logGroupName,
    )
    try:
        retention = response["logGroups"][0]["retentionInDays"]
    except Exception:
        retention = -1

    if retention < 0:
        try:
            logsclient.put_retention_policy(
                logGroupName=logGroupName, retentionInDays=365
            )
            responses["EnableLogging"].append(
                {
                    "Action": "put_retention_policy",
                    "Message": f"Log Group {logGroupName} now has a 1 year retention period",
                }
            )
        except Exception as error:
            responses["EnableLogging"].append(
                {
                    "Action": "put_retention_policy",
                    "Message": f"ERROR Log Group {logGroupName} unable to set retention period - {error.response['Error']['Code']}",
                }
            )
            pass

    return f"arn:aws:logs:{region}:{AwsAccountId}:log-group:{logGroupName}"


if __name__ == "__main__":
    event = {
        "AccountId": "211125410042",
        "ResourceId": "arn:aws:cloudfront::211125410042:distribution/E1ZVJNXBU1SKT5",
        "Region": "us-east-1",
        "ResourceType": "AwsCloudFrontDistribution",
        "LoggingBucket": "asr-logging-cloudfront-211125410042-us-east-1",
    }
    result = runbook_handler(event, "")
    print(result)
