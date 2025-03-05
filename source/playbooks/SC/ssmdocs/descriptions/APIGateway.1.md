### Document Name - ASR-SC_2_0_0_APIGateway.1

## What does this document do?

This document sets the logging level for the given API Gateway stage to the `loggingLevel` set in the Security Hub control parameters, otherwise "INFO".

## Input Parameters

- Finding: (Required) Security Hub finding details JSON
- AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.
- Region: The REGION of the resource
- AccountId: The Account Id of the resource
- ResourceType: The Type of the resource (ie AwsApiGatewayStage for REST and AwsApiGatewayV2Stage for v2)

## Output Parameters

- Remediation.Output - Output from the remediation

## Documentation Links

- [APIGateway.1](https://docs.aws.amazon.com/securityhub/latest/userguide/apigateway-controls.html#apigateway-1)
