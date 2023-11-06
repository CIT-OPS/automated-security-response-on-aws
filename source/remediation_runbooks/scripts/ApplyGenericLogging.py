import logging
import copy
import json
import time
from pprint import pprint
import botocore
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config


def runbook_handler(event, context):
  ResourceId = event['ResourceId']  
  # arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/XPVA-TstAR2-DID-DEV1/25d1f4f34ae00664
  # arn:aws:apigateway:us-east-1::/restapis/2abcdefghi/stages/prod

  ResourceSplit = ResourceId.split(":")
  serviceName = ResourceSplit[2]
  if serviceName == 'elasticloadbalancing':
    serviceName = 'elb'
  region = event['Region']
  AwsAccountId = event['AccountId']
  ResourceType = event['ResourceType']
  
  loggingBucket = 'sharr-logging-' + serviceName + '-' + AwsAccountId + '-' + region.lower()

  if ResourceType == 'AwsElbv2LoadBalancer':
    client = boto3.client('elbv2', region_name = region)
    try:
        client.modify_load_balancer_attributes(
            LoadBalancerArn=ResourceId,
            Attributes=[
                {'Key': 'access_logs.s3.enabled','Value': 'true'},
                {'Key': 'access_logs.s3.bucket','Value': loggingBucket},
            ]
        )
        return {
            'message': 'ELB Resource Modified for logging',
            'status': 'RESOLVED'
        }
    except Exception as e:
        print("Unable to set logging on elbv2")
        print(e)

  if ResourceType == "AwsApiGatewayStage":
    try:
        apigwclient = boto3.client('apigateway',region_name=region)   #Use V2 for Websocket and V1 for Rest
        apigwArray = ResourceSplit[5].split('/')
        ApiId = apigwArray[2]
        stageName = apigwArray[4]

        # Make sure API Gateway Account level settings have Cloudwatch Role
        setupAPIGatewayAccountSettings(AwsAccountId, apigwclient)
        
        # Get/Create Log Group for access and execution logging
        accesslogGroupArn = createLogGroup('API-Gateway-Access-Logs_'+ApiId+'/'+stageName, region, AwsAccountId)
        #executelogGroupArn = createLogGroup('/aws/apigateway/execution/'+ApiId+'/'+stageName, region, AwsAccountId)
        
        # Get the current Stage Info and figure out whats needed
        response = apigwclient.get_stage(restApiId=ApiId, stageName=stageName)
        
        # Access Logging required?
        try:
            accessLogSettings = response['accessLogSettings']['destinationArn']
            if accessLogSettings != '':
                setAccessLogging = False
            else:
                setAccessLogging = True
        except Exception as e:
            setAccessLogging = True
            pass

        # Execute Logging Required?
        try:
            methodSettings = response['methodSettings']['*/*']['loggingLevel']
            if methodSettings == 'OFF':
                setMethodLogging = True
            else:
                setMethodLogging = False
        except Exception as e:
            setMethodLogging = True
            pass

        # XRay Tracing Required?
        try:
            xray = response['tracingEnabled']
            if xray == False:
                setXray = True
            else:
                setXray = False
        except Exception as e:
            setXray = True
            pass

        # Build up an array of items to patch
        PatchOperations = []
        if setAccessLogging:
            operation = {
                'op': 'replace',
                'path': '/accessLogSettings/destinationArn',
                'value': accesslogGroupArn,
                #'from': 'string'
            }
            PatchOperations.append(operation)
            operation = {
                'op': 'replace',
                'path': '/accessLogSettings/format',
                'value': '{ "requestId":"$context.requestId", "ip": "$context.identity.sourceIp", "caller":"$context.identity.caller", "user":"$context.identity.user","requestTime":"$context.requestTime", "httpMethod":"$context.httpMethod","resourcePath":"$context.resourcePath", "status":"$context.status","protocol":"$context.protocol", "responseLength":"$context.responseLength" }',
                #'from': 'string'
            }
            PatchOperations.append(operation)
        if setXray:
            operation = {
                'op': 'replace',
                'path': '/tracingEnabled',
                'value': 'true',
            }
            PatchOperations.append(operation)
        if setMethodLogging:
            operation = {
                'op': 'replace',
                'path': '/*/*/logging/loglevel',
                'value': 'ERROR',
            }
            PatchOperations.append(operation)

        # If there are items to patch, then patch them!
        if len(PatchOperations) > 0:
            print("[INFO] The following Patch operations to the stage {stageName} will occur")
            for operation in PatchOperations:
                print(operation) 

            try:
                apigwclient.update_stage(
                    restApiId=ApiId,
                    stageName=stageName,
                    patchOperations=PatchOperations
                )
            except Exception as error:
                print(error)
                return {
                    'message': error,
                    'status': 'ERROR'
                }
        else:
            print("[ERROR] No Patch operations required for APIGateway - Why was remediation requested?")

        return {
            'message': 'API Gateway modified for logging',
            'status': 'RESOLVED'
        }
    except Exception as e:
        print("Unable to set logging on APIGateway")
        print(e)
        return {
            'message': f'Unable to set up logging on APIGW {e}',
            'status': 'ERROR'
        }

  if ResourceType == "AwsApiGatewayV2Stage":
    try:
        apigwclientv2 = boto3.client('apigatewayv2',region_name=region) 
        apigwclientv1 = boto3.client('apigateway',region_name=region) 
        apigwArray = ResourceSplit[5].split('/')
        ApiId = apigwArray[2]
        stageName = apigwArray[4]

        # Make sure API Gateway Account level settings have Cloudwatch Role
        setupAPIGatewayAccountSettings(AwsAccountId, apigwclientv1)     # uses v1 settings for account level
        
        # Get/Create Log Group for access and execution logging
        accesslogGroupArn = createLogGroup('API-Gateway-Access-Logs_'+ApiId+'/'+stageName, region, AwsAccountId)

        # Get some info on the API
        response = apigwclientv2.get_api(ApiId=ApiId)
        ProtocolType = response['ProtocolType']
        if ProtocolType != "HTTP" and ProtocolType != "WEBSOCKET":
            exit(f"Invalid Protocol type on API [{ProtocolType}]")
        
        
        # Get the current Stage Info and figure out whats needed
        response = apigwclientv2.get_stage(ApiId=ApiId, StageName=stageName)    # Params differ v1 to v2
        
        # Access Logging required?
        setAccessLogging = True
        if 'AccessLogSettings' in response:
            if 'DestinationArn' in response['AccessLogSettings']:
                accessLogSettings = response['AccessLogSettings']['DestinationArn']
                if accessLogSettings != '':
                    setAccessLogging = False

        # Execute Logging Required?
        try:
            methodSettings = response['DefaultRouteSettings']['LoggingLevel']
            if methodSettings == 'OFF':
                setMethodLogging = True
            else:
                setMethodLogging = False
        except Exception as e:
            setMethodLogging = True
            pass

        # XRay Tracing Required?
        setXray = False
        # try:
        #     xray = response['DefaultRouteSettings']['LoggingLevel']
        #     if xray == False:
        #         setXray = True
        #     else:
        #         setXray = False
        # except Exception as e:
        #     setXray = True
        #     pass

        # Build up an array of items to patch
        PatchOperations = {}
        if setAccessLogging:
            operation = {}
            operation['DestinationArn'] = accesslogGroupArn
            operation['Format'] = '{ "requestId":"$context.requestId", "ip": "$context.identity.sourceIp", "caller":"$context.identity.caller", "user":"$context.identity.user","requestTime":"$context.requestTime", "httpMethod":"$context.httpMethod","resourcePath":"$context.resourcePath", "status":"$context.status","protocol":"$context.protocol", "responseLength":"$context.responseLength" }'
            PatchOperations['AccessLogSettings'] = operation
            
        # if setXray:
        #     operation = {
        #         'op': 'replace',
        #         'path': '/tracingEnabled',
        #         'value': 'true',
        #     }
        #     PatchOperations.append(operation)
        
        if setMethodLogging and ProtocolType == 'WEBSOCKET':
            operation = {}
            operation['LoggingLevel'] = 'ERROR'
            PatchOperations['DefaultRouteSettings'] = operation

        # If there are items to patch, then patch them!
        if len(PatchOperations) > 0:
            PatchOperations['ApiId'] = ApiId
            PatchOperations['StageName'] = stageName

            print(f"[INFO] The following Patch operations to the stage {stageName} will occur")
            print(PatchOperations)

            try:
                apigwclientv2.update_stage(**PatchOperations)
            except Exception as error:
                print(error)
                return {
                    'message': error,
                    'status': 'ERROR'
                }
        else:
            print("[ERROR] No Patch operations required for APIGateway - Why was remediation requested?")

        return {
            'message': 'API Gateway modified for logging',
            'status': 'RESOLVED'
        }
    except Exception as e:
        print("Unable to set logging on APIGateway")
        print(e)
        return {
            'message': f'Unable to set up logging on APIGW {e}',
            'status': 'ERROR'
        }

  if ResourceType == "AwsCloudFrontDistribution":
        DEBUG = False
        
        distributionSplit = ResourceSplit[5].split('/')
        distributionId = distributionSplit[1]

        # Get the current Distribution Config
        # To update a web distribution using the CloudFront API
        #   Use GetDistributionConfig to get the current configuration, including the version identifier ( ETag).
        #   Update the distribution configuration that was returned in the response. Note the following important requirements and restrictions:
        #   You must rename the ETag field to IfMatch, leaving the value unchanged. (Set the value of IfMatch to the value of ETag, then remove the ETag field.)
        #   You can’t change the value of CallerReference.
        #   Submit an UpdateDistribution request, providing the distribution configuration. The new configuration replaces the existing configuration. The values that you specify in an UpdateDistribution request are not merged into your existing configuration. Make sure to include all fields: the ones that you modified and also the ones that you didn’t.

        # Permissions required:  
        # remediationPolicy2.addActions('cloudfront:GetDistribution*', 'cloudfront:UpdateDistribution');

        cloudfrontClient = boto3.client('cloudfront')
        response = cloudfrontClient.get_distribution(Id=distributionId)
        print(f"Distribution {distributionId} currently has a status of {response['Distribution']['Status']}")
        if response['Distribution']['Status'] != "Deployed":
            exit("cannot update cloudfront config when its status is {response['Distribution']['Status']}")

        print(f"Getting current distribution config for {distributionId}")
        distroConfig = response = cloudfrontClient.get_distribution_config(Id=distributionId)
        ETag = distroConfig["ETag"]
        distroConfig.pop("ETag")                # Get rid of this.  Actually change it to IfMatch 
        distroConfig.pop("ResponseMetadata")    # No use for this info, and not to be passed back
        distroConfig["IfMatch"] = ETag
        #printObject = printJson(distroConfig) if DEBUG is True else None
        
        updateDefaultRoot = True
        if 'DefaultRootObject' in distroConfig['DistributionConfig']:
            if distroConfig['DistributionConfig']['DefaultRootObject'] != "":
                updateDefaultRoot = False

        if updateDefaultRoot:
            distroConfig['DistributionConfig']['DefaultRootObject'] = "index.html"
            print(f"Updating DefaultRootObject from None to 'index.html' because security hub thinks its a necessary security precaution.")
        else:
            print(f"DefaultRootObject remains as {distroConfig['DistributionConfig']['DefaultRootObject']}")

        ViewerProtocolPolicy = distroConfig['DistributionConfig']['DefaultCacheBehavior']['ViewerProtocolPolicy']
        if ViewerProtocolPolicy == 'allow-all':
            print(f"Updating ViewerProtocolPolicy from 'allow-all' to 'redirect-to-https' for better 'security'")
            distroConfig['DistributionConfig']['DefaultCacheBehavior']['ViewerProtocolPolicy'] = 'redirect-to-https'
        else:
            print(f"ViewerProtocolPolicy of '{ViewerProtocolPolicy}' meets security requirement for https")

        # Using SNI?
        if distroConfig['DistributionConfig']['Aliases']['Quantity'] > 0:
            SSLSupportMethod = distroConfig['DistributionConfig']['ViewerCertificate']['SSLSupportMethod']
            MinimumProtocolVersion = distroConfig['DistributionConfig']['ViewerCertificate']['MinimumProtocolVersion']
            DesiredProtocolVersion = 'TLSv1.2_2021'
            if SSLSupportMethod != "sni-only":
                print(f"[ERROR] CLOUDFRONT CONFIGURED WITH A NON STANDARD EXPENSIVE OPTION  (SSLSupportMethod={SSLSupportMethod})")
            if MinimumProtocolVersion != DesiredProtocolVersion:
                print(f"Updating Cloudfront viewer certificate, minimum security protocol requirement from {MinimumProtocolVersion} to {DesiredProtocolVersion}")
                distroConfig['DistributionConfig']['ViewerCertificate']['MinimumProtocolVersion'] = DesiredProtocolVersion
        else:
            print(f"WARNING - You are not supposed to use the default domain name;  Please update to use a custom domain name (SNI)")

        # http version http/2 and http/3
        if distroConfig['DistributionConfig']['HttpVersion'] != "http2and3":
            print("Updating maximum viewer configuration to allow up to HTTP/3 with TLS 1.3")
            distroConfig['DistributionConfig']['HttpVersion'] = "http2and3"

        if distroConfig['DistributionConfig']['Comment'] == "":
            distroConfig['DistributionConfig']['Comment'] = "FIXME - You should really have a description for what this cloudfront does!"

        if distroConfig['DistributionConfig']['Logging']['Enabled'] == False:
            distroConfig['DistributionConfig']['Logging']['Enabled'] = True
            distroConfig['DistributionConfig']['Logging']['IncludeCookies'] = True
            distroConfig['DistributionConfig']['Logging']['Bucket'] = event['LoggingBucket']+'.s3.amazonaws.com'
            distroConfig['DistributionConfig']['Logging']['Prefix'] = AwsAccountId+"/"
            print(f"Set logging to bucket to {event['LoggingBucket']}")

        if 'Id' not in distroConfig:
            distroConfig['Id'] = distributionId


        printObject = printJson(distroConfig) if DEBUG is True else None
        
        response = cloudfrontClient.update_distribution(**distroConfig)
        return {
            'message': 'Cloudfront logging and other defaults set',
            'status': 'RESOLVED'
        }

  return {
        'message': 'UNKNOWN Service requested for logging - IGNORED',
        'status': 'ERROR'
  }

def printJson(object):
    json_formatted_str = json.dumps(object, indent=2)
    print(json_formatted_str)
    return

def setupAPIGatewayAccountSettings(AwsAccountId, apigwclient):
    response = apigwclient.get_account()
    if 'cloudwatchRoleArn' not in response:
        # Create a cloudwatch role and assign it to account
        iamClient = boto3.client('iam')
        roleName = 'APIGatewayLogWriterRole'
        try:
            iamClient.create_role(
                RoleName=roleName,
                AssumeRolePolicyDocument='{"Version": "2012-10-17","Statement": [{"Sid": "","Effect": "Allow","Principal": {"Service": ["apigateway.amazonaws.com"]},"Action": ["sts:AssumeRole"]}]}',
                Description='A role which allows API Gateway to write to CloudWatch Logs'
            )

        except botocore.exceptions.ClientError as error:
            # Put your error handling logic here
            if error.response['Error']['Code'] == 'EntityAlreadyExists':
                print(f"[INFO] The role {roleName} already exists... proceeding")
            else:
                print(error)
            pass

        #Attach Permission to Role
        try:
            iamClient.attach_role_policy(
                RoleName=roleName,
                PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs'
            )
        except Exception as e:
            print(e)
            pass
        print(f"[INFO] Role {roleName} created and/or updated")
        try:
            response = apigwclient.update_account(
                patchOperations=[
                    {
                        'op': 'replace',
                        'path': '/cloudwatchRoleArn',
                        'value': f"arn:aws:iam::{AwsAccountId}:role/APIGatewayLogWriterRole",
                        #'from': 'string'
                    },
                ]
            )
        except Exception as e:
            print(e)
            pass
    else:
        print('[INFO] Cloudwatch Role already exists for API Gateway Account Settings... skipping Role Creation')
    return

def createLogGroup(logGroupName, region, AwsAccountId):
    logGroupName = logGroupName.replace('$default','dollar_default')
    try:
        logsclient = boto3.client('logs',region_name=region)
        response = logsclient.create_log_group(
            logGroupName=logGroupName,
            tags={
                'CreatedBy': 'SHARR'
            }
        )
    except botocore.exceptions.ClientError as error:
        # Put your error handling logic here
        # print(error.response['Error']['Code'])
        if error.response['Error']['Code'] == 'ResourceAlreadyExistsException':
            print(f"[INFO] The log Group {logGroupName} already exists... proceeding")
        else:
            print(error)
        pass
    
    # Get log Group Info
    response = logsclient.describe_log_groups(
        logGroupNamePrefix=logGroupName,
    )
    try:
        retention = response['logGroups'][0]['retentionInDays']
    except Exception as error:
        retention = -1

    if retention < 0:
        try:
            logsclient.put_retention_policy(
                logGroupName=logGroupName,
                retentionInDays=365
            )
            print(f"[INFO] Adding Retention Period of 1 year days to {logGroupName}")
        except Exception as error:
            print(f"[ERROR] Failed to add Retention Period of 1 year to {logGroupName} {error}")

    return f"arn:aws:logs:{region}:{AwsAccountId}:log-group:{logGroupName}" 


if __name__ == "__main__":
    event = {
       "ResourceId": "arn:aws:elasticloadbalancing:us-east-1:455768319323:loadbalancer/app/i-coreOps-proxy-lb/1533f03526fc680f",
       "LoggingBucket": "sharr-logging-elb-455768319323-us-east-1",
       "ResourceType": "AwsElbv2LoadBalancer",
       "AccountId": "455768319323",
       "Region": "us-east-1",
    }
    result = runbook_handler(event,"")
    print(result)