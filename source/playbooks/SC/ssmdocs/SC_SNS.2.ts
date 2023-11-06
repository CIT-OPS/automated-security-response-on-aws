// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { DataTypeEnum, HardCodedString, Output, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableDeliveryLoggingForSNSTopicDocument(scope, id, { ...props, controlId: 'SNS.2' });
}

export class EnableDeliveryLoggingForSNSTopicDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    // const docInputs = [
    //   Input.ofTypeString('LoggingRole', {
    //     allowedPattern: String.raw`^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role/[\w+=,.@-]+$`,
    //     defaultValue: '{{ssm:/Solutions/SO0111/DeliveryStatusLoggingRole}}',
    //   }),
    // ];

    super(scope, id, {
      ...props,
      //docInputs,
      securityControlId: 'SNS.2',
      remediationName: 'EnableSNSDeliveryLogging',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'SNSTopicArn',
      updateDescription: HardCodedString.of('Delivery Status Logging enabled on SNS Topic'),
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
  
      return outputs;
    }
  

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();
    params.SNSTopicArn = StringVariable.of('ParseInput.SNSTopicArn');
    params.Region = StringVariable.of('ParseInput.Region');
    return params;
  }
}
