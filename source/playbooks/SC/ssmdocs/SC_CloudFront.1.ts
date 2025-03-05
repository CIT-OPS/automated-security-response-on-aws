// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, DataTypeEnum, Output, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableCloudFrontDefaultRootObjectDocument(scope, id, { ...props, controlId: 'CloudFront.1' });
}

export class EnableCloudFrontDefaultRootObjectDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'CloudFront.1',
      otherControlIds: ['CloudFront.3', 'CloudFront.5'], // CNXC Added the otherControlIds
      // remediationName: 'EnableCloudFrontDefaultRootObject',
      remediationName: 'CNXC_EnableCloudfrontLogging', // CNXC Changed the remediationName to a Concentrix one
      scope: RemediationScope.GLOBAL,
      // resourceIdName: 'CloudFrontDistribution',
      resourceIdName: 'ResourceId', // CNXC Changed the resourceIdName
      resourceIdRegex: String.raw`^(arn:(?:aws|aws-us-gov|aws-cn):cloudfront::\d{12}:distribution\/([A-Z0-9]+))$`,
      // updateDescription: HardCodedString.of('Configured default root object for CloudFront distribution'),
      updateDescription: HardCodedString.of('Configured CloudFront distribution'), // CNXC Override the updateDescription
    });
  }

  // Start CNXC Changes
  /** @override */
  protected override getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();
    // outputs.push({
    //   name: 'RemediationAccount',
    //   outputType: DataTypeEnum.STRING,
    //   selector: '$.Payload.account_id',
    // });

    outputs.push({
      name: 'ResourceType',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.object.Type',
    });
    return outputs;
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();
    params.Region = StringVariable.of('global:REGION');
    params.AccountId = StringVariable.of('global:ACCOUNT_ID');
    params.ResourceType = StringVariable.of('ParseInput.ResourceType');
    return params;
  }
  // End CNXC Changes
}
