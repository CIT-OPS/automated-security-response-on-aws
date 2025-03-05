// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import {
  DataTypeEnum,
  Output,
  //AutomationStep,
  //DataTypeEnum,
  //Output,
  StringFormat,
  //StringListVariable,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new CNXC_EnableAPIGatewayLoggingDocument(scope, id, { ...props, controlId: 'APIGateway.1' });
  //return new EnableAPIGatewayExecutionLogsDocument(scope, id, { ...props, controlId: 'APIGateway.1' });
}

export class CNXC_EnableAPIGatewayLoggingDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'APIGateway.1',
      otherControlIds: ['APIGateway.3', 'APIGateway.9'], // CNXC
      //remediationName: 'EnableAPIGatewayExecutionLogs', // CNXC
      remediationName: 'CNXC_EnableAPIGatewayLogging', // CNXC
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'ResourceId',
      resourceIdRegex: String.raw`(.*)$`,
      header:
        'Copyright Concentrix CVG LLC or its affiliates. All Rights Reserved.\nSPDX-License-Identifier: Apache-2.0',
      updateDescription: new StringFormat('Log level set to %s in Stage.', [
        StringVariable.of(`GetInputParams.loggingLevel`),
      ]),
    });
  }

  // Start CNXC Changes
  /** @override */
  protected override getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    outputs.push({
      name: 'ResourceType',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.object.Type',
    });
    return outputs;
  }

  protected override getRemediationParams(): Record<string, any> {
    const params: Record<string, any> = super.getRemediationParams();
    params.Region = StringVariable.of('global:REGION');
    params.AccountId = StringVariable.of('global:ACCOUNT_ID');
    params.ResourceType = StringVariable.of('ResourceType');
    return params;
  }
}
