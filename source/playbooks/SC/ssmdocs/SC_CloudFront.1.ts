// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
} from '@cdklabs/cdk-ssm-documents'; // CNXC Changed the import path

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableCloudFrontDefaultRootObjectDocument(scope, id, { ...props, controlId: 'CloudFront.1' });
}

export class EnableCloudFrontDefaultRootObjectDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'CloudFront.1',
      otherControlIds: ['CloudFront.3', 'CloudFront.5'], // CNXC Added the otherControlIds
      remediationName: 'CNXC_EnableCloudfrontLogging', // CNXC Changed the remediationName to a Concentrix one
      scope: RemediationScope.GLOBAL,
      //resourceIdName: 'CloudFrontDistribution', // CNXC Changed the resourceIdName
      resourceIdName: 'ResourceId', // CNXC Changed the resourceIdName
      resourceIdRegex: String.raw`^(arn:(?:aws|aws-us-gov|aws-cn):cloudfront::\d{12}:distribution\/([A-Z0-9]+))$`,
      updateDescription: HardCodedString.of('Configured CloudFront distribution'), // CNXC Override the updateDescription
    });
  }

  // Start CNXC Changes
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
    // End CNXC Changes
  }
}
