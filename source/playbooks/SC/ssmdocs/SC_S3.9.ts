// CONCENTRIX CODE
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import {
  AutomationStep,
  AwsApiStep,
  AwsService,
  // AutomationStep,
  // AwsApiStep,
  // AwsService,
  // BranchStep,
  // Choice,
  DataTypeEnum,
  //ExecuteScriptStep,
  HardCodedString,
//  Operation,
  Output,
  // ScriptCode,
  // ScriptLanguage,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents';
// import path = require('path');
// import * as fs from 'fs';


export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new ConfigureS3ServerAccessLoggingDocument(scope, id, { ...props, controlId: 'S3.9' });
}

class ConfigureS3ServerAccessLoggingDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'S3.9',
      remediationName: 'ConfigureS3ServerAccessLogging',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'BucketName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):s3:::([A-Za-z0-9.-]{3,63})$`,
      updateDescription: HardCodedString.of('Configured S3 Server Access Logging'),
      header: 'Copyright Concentrix CVG LLC or its affiliates. All Rights Reserved.\nSPDX-License-Identifier: Apache-2.0',      
    });
  }

  /** @override */
  protected getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    // outputs.push({
    //   name: 'Resource',
    //   outputType: DataTypeEnum.STRING_MAP,
    //   selector: '$.Payload.resource',
    // });

    // outputs.push({
    //   name: 'Finding',
    //   outputType: DataTypeEnum.STRING_MAP,
    //   selector: '$.Payload.finding',
    // });

    outputs.push({
      name: 'AccountId',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.account_id',
    });

    outputs.push({
      name: 'Region',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.resource.Region',
    });

    return outputs;
  }



  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.BucketName = StringVariable.of('ParseInput.BucketName');
    params.Region = StringVariable.of('ParseInput.Region');
    params.AccountId = StringVariable.of('ParseInput.AccountId');

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
