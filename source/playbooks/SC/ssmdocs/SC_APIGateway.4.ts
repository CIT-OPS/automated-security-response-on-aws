// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import {
  // AutomationStep,
  // AwsApiStep,
  // AwsService,
  DataTypeEnum,
  HardCodedString,
  Output,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents'; // CNXC Changed the import path

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableCloudFrontAPIGWWAFDocument(scope, id, { ...props, controlId: 'APIGateway.4' });
}

export class EnableCloudFrontAPIGWWAFDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'APIGateway.4',
      otherControlIds: ['CloudFront.6'],
      remediationName: 'CNXC_AssignWAFToResource',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'ResourceId',
      resourceIdRegex: String.raw`(.*)$`,
      updateDescription: HardCodedString.of('Configured WAF on resource'),
    });
  }

  /** @override */
  protected getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    // outputs.push({
    //   name: 'Region',
    //   outputType: DataTypeEnum.STRING,
    //   selector: '$.Payload.resource.Region',
    // });

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

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.Region = StringVariable.of('global:REGION');
    params.AccountId = StringVariable.of('global:ACCOUNT_ID');
    params.ResourceType = StringVariable.of('ParseInput.ResourceType');
    return params;
  }
  // End CNXC Changes
}
