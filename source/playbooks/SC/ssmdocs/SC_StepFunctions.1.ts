/* eslint-disable header/header */
// Copyright CONCENTRIX. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { DataTypeEnum, HardCodedString, Output, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new CNXC_EnableStepFunctionLoggingDocument(scope, id, { ...props, controlId: 'StepFunctions.1' });
}

class CNXC_EnableStepFunctionLoggingDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'StepFunctions.1',
      remediationName: 'CNXC_EnableStepFunctionLogging',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'ResourceId',
      resourceIdRegex: String.raw`(.*)$`,
      updateDescription: HardCodedString.of('Enabled Stepfunction logging'),
      header:
        'Copyright Concentrix CVG LLC or its affiliates. All Rights Reserved.\nSPDX-License-Identifier: Apache-2.0',
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
}
