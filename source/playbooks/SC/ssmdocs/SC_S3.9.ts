// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { DataTypeEnum, HardCodedString, Output, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new ConfigureS3BucketLoggingDocument(scope, id, {
    ...props,
    controlId: 'S3.9',
  });
}

export class ConfigureS3BucketLoggingDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'S3.9',
      remediationName: 'CNXC_ConfigureS3ServerAccessLogging',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'BucketName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):s3:::([A-Za-z0-9.-]{3,63})$`,
      updateDescription: HardCodedString.of('Added Server Access Logging to S3 bucket.'),
    });
  }

  /** @override */
  protected getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    outputs.push({
      name: 'Region',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.resource.Region',
    });

    outputs.push({
      name: 'AccountId',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.account_id',
    });

    return outputs;
  }

  // /** @override */
  // protected getRemediationStep(): AutomationStep {
  //   return new ExecuteAutomationStep(this, 'Remediation', {
  //     documentName: HardCodedString.of(`AWS-${this.remediationName}`),
  //     runtimeParameters: HardCodedStringMap.of(this.getRemediationParams()),
  //   });
  // }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();
    params.Region = StringVariable.of('ParseInput.Region');
    params.AccountId = StringVariable.of('ParseInput.AccountId');
    params.BucketName = StringVariable.of('ParseInput.BucketName');
    return params;
  }
}
