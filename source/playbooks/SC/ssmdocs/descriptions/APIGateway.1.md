### Document Name - ASR-AFSBP_1.0.0_APIGateway.1

## What does this document do?
 This document checks whether the stage of an Amazon API Gateway REST and WebSocket APIs have logging enabled. The control will remediate if logging is not enabled for all methods of a stage or if loggingLevel is neither ERROR nor INFO.  It will also look for and set X-Ray tracing.

## Input Parameters  FIXME
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters
* Remediation.Output

## Documentation Links
* [AFSBP APIGateway.1](https://docs.aws.amazon.com/securityhub/latest/userguide/apigateway-controls.html#apigateway-1)
