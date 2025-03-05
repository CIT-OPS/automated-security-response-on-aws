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
  return new CNXC_EnableAPIGatewayLoggingDocument(scope, id, { ...props, controlId: 'APIGateway.1' });
}

class CNXC_EnableAPIGatewayLoggingDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'APIGateway.1',
      otherControlIds: ['APIGateway.3', 'APIGateway.9'],
      remediationName: 'CNXC_EnableAPIGatewayLogging',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'ResourceId',
      resourceIdRegex: String.raw`(.*)$`,
      updateDescription: HardCodedString.of('Enabled API Gateway execution logging'),
      header:
        'Copyright Concentrix CVG LLC or its affiliates. All Rights Reserved.\nSPDX-License-Identifier: Apache-2.0',
    });
  }

  protected override getExtraSteps(): AutomationStep[] {
    return [
      super.getInputParamsStep({
        loggingLevel: 'INFO',
      }),
    ];
  }

  protected override getInputParamsStepOutput(): Output[] {
    const loggingLevel: Output = {
      name: 'loggingLevel',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.loggingLevel',
    };

    return [loggingLevel];
  }
  protected override getRemediationParams(): Record<string, any> {

    const params: Record<string, any> = super.getRemediationParams();

    params.LoggingLevel = StringListVariable.of('GetInputParams.loggingLevel');

    params.Region = StringVariable.of('ParseInput.Region');
    params.AccountId = StringVariable.of('ParseInput.AccountId');
    params.ResourceType = StringVariable.of('ParseInput.ResourceType');
    return params;
  }
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
