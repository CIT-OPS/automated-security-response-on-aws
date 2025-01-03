/* eslint-disable header/header */
// Copyright CONCENTRIX. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import {
  AutomationStep,
  AwsApiStep,
  AwsService,
  DataTypeEnum,
  HardCodedString,
  Output,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new CNXC_EnableDynamoDB_PITRDocument(scope, id, { ...props, controlId: 'DynamoDB.2' });
}

class CNXC_EnableDynamoDB_PITRDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    const remediationName = 'CNXC_EnableDynamoDB_PITR';
    super(scope, id, {
      ...props,
      securityControlId: 'DynamoDB.2',
      remediationName,
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'TableArn',
      resourceIdRegex: String.raw`(.*)$`,
      updateDescription: HardCodedString.of(
        `Enabled PITR on table using the ${props.solutionAcronym}-${remediationName} runbook.`,
      ),
      header:
        'Copyright Concentrix CVG LLC or its affiliates. All Rights Reserved.\nSPDX-License-Identifier: Apache-2.0',
    });
  }

  /** @override */
  protected getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    outputs.push({
      name: 'TableRegion',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.resource.Region',
    });

    return outputs;
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.TableArn = StringVariable.of('ParseInput.TableArn');
    return params;
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getUpdateFindingStep(): AutomationStep {
    return new AwsApiStep(this, 'UpdateFinding', {
      service: AwsService.SECURITY_HUB,
      pascalCaseApi: 'BatchUpdateFindings',
      apiParams: {
        FindingIdentifiers: [
          {
            Id: StringVariable.of('ParseInput.FindingId'),
            ProductArn: StringVariable.of('ParseInput.ProductArn'),
          },
        ],
        Note: {
          Text: this.updateDescription,
          UpdatedBy: this.documentName,
        },
        Workflow: { Status: 'RESOLVED' },
      },
      outputs: [],
      isEnd: true,
    });
  }
}