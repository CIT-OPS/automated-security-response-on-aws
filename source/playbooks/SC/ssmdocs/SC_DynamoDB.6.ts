/* eslint-disable header/header */
// Copyright CONCENTRIX. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new CNXC_EnableDynamoDB_DeleteProtection(scope, id, { ...props, controlId: 'DynamoDB.6' });
}

class CNXC_EnableDynamoDB_DeleteProtection extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    const remediationName = 'CNXC_EnableDynamoDB_DeleteProtection';
    super(scope, id, {
      ...props,
      securityControlId: 'DynamoDB.6',
      remediationName,
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'TableArn',
      resourceIdRegex: String.raw`(.*)$`,
      updateDescription: HardCodedString.of(
        `Enabled delete protection on table using the ${props.solutionAcronym}-${remediationName} runbook.`,
      ),
      header:
        'Copyright Concentrix CVG LLC or its affiliates. All Rights Reserved.\nSPDX-License-Identifier: Apache-2.0',
    });
  }

  /** @override */
  // protected getParseInputStepOutputs(): Output[] {
  //   const outputs = super.getParseInputStepOutputs();

  //   outputs.push({
  //     name: 'RemediationRegion',
  //     outputType: DataTypeEnum.STRING,
  //     selector: '$.Payload.resource.Region',
  //   });

  //   return outputs;
  // }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();
    // params.Region = StringVariable.of('ParseInput.RemediationRegion');
    params.TableArn = StringVariable.of('ParseInput.TableArn');
    return params;
  }
}
