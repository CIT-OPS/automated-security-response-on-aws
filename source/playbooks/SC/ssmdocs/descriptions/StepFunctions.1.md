### Document Name - ASR-SC.StepFunctions.1

## What does this document do?
This document is invoked to enable logging of step functions.  If the stepfunction already has a cloudwatch logs destination
it will use that or make up a standardized name.   It will also ensure that the step function execution role has permission
to write to the cloudwatch logs.

## Input Parameters  FIXME
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters
* Remediation.Output

## Documentation Links
* [StepFunctions.1](https://docs.aws.amazon.com/console/securityhub/StepFunctions.1/remediation)
