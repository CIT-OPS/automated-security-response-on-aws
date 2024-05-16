// CONCENTRIX CODE
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
  return new EnableAPIGatewayWAF(scope, id, { ...props, controlId: 'APIGateway.4' });
}

class EnableAPIGatewayWAF extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'APIGateway.4',
    //   otherControlIds: [
    //     'APIGateway.3',
    //     'APIGateway.9',
    //   ],
      remediationName: 'AssignWAFToResource',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'ResourceId',
      resourceIdRegex: String.raw`(.*)$`,
      updateDescription: HardCodedString.of('Enabled API Gateway WAF Association'),
      header: 'Copyright Concentrix CVG LLC or its affiliates. All Rights Reserved.\nSPDX-License-Identifier: Apache-2.0',      
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

    params.Region = StringVariable.of('ParseInput.Region');
    params.AccountId = StringVariable.of('ParseInput.AccountId');
    params.ResourceType = StringVariable.of('ParseInput.ResourceType');
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
