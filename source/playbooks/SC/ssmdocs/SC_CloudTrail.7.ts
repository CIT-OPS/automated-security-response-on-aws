// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import {
  AutomationStep,
  AwsApiStep,
  AwsService,
  BranchStep,
  Choice,
  DataTypeEnum,
  ExecuteAutomationStep,
  HardCodedString,
  HardCodedStringMap,
  IStringVariable,
  Operation,
  StringFormat,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new ConfigureS3BucketLoggingDocument(scope, id, {
    ...props,
    controlId: 'CloudTrail.7',
    otherControlIds: ['S3.9'],
  });
}

export class ConfigureS3BucketLoggingDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    const resourceIdName = 'BucketName';

    super(scope, id, {
      ...props,
      securityControlId: 'CloudTrail.7',
      remediationName: 'ConfigureS3BucketLogging',
      scope: RemediationScope.GLOBAL,
      resourceIdName,
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):s3:::([A-Za-z0-9.-]{3,63})$`,
      updateDescription: new StringFormat('Created S3 bucket %s for logging access to %s', [
        getTargetBucketName(props.solutionId),
        StringVariable.of(`ParseInput.${resourceIdName}`),
      ]),
    });
  }

  suppressBucket = new AwsApiStep(this, 'api', {
    service: AwsService.STS,
    pascalCaseApi: 'getCallerIdentity',
    apiParams: {},
    isEnd: true,
    outputs: [
      {
        outputType: DataTypeEnum.STRING,
        name: 'User',
        selector: '$.UserId',
      },
    ],
  });

  /** @override */
  protected getExtraSteps(): AutomationStep[] {
    const createAccessLoggingBucketStepName = 'CreateAccessLoggingBucket';
    const createAccessLoggingBucketStep = new ExecuteAutomationStep(this, createAccessLoggingBucketStepName, {
      documentName: HardCodedString.of(`${this.solutionAcronym}-${createAccessLoggingBucketStepName}`),
      runtimeParameters: HardCodedStringMap.of({
        BucketName: getTargetBucketName(this.solutionId),
        AutomationAssumeRole: new StringFormat(
          `arn:%s:iam::%s:role/${this.solutionId}-${createAccessLoggingBucketStepName}`,
          [StringVariable.of('global:AWS_PARTITION'), StringVariable.of('global:ACCOUNT_ID')],
        ),
      }),
    });

    const suppressRemediation = new AwsApiStep(this, 'SuppressFinding', {
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
          Text: 'Remediation was suppressed because the bucket to log to is the same as the affected object.',
          UpdatedBy: this.documentName,
        },
        Workflow: { Status: 'SUPPRESSED' },
      },
      outputs: [],
      isEnd: true,
    });

    const branchStep = new BranchStep(this, 'IsALoggingBucket', {
      name: 'IsALoggingBucket',
      description: 'Suppress if the bucket to log to is the same as the affected object',
      defaultStepName: createAccessLoggingBucketStep.name,
      choices: [
        new Choice({
          operation: Operation.STRING_EQUALS,
          variable: StringVariable.of('ParseInput.BucketName'),
          constant: 'cnxc-s3-server-access-logging-{{ global:ACCOUNT_ID }}-{{ global:REGION }}',
          jumpToStepName: suppressRemediation.name,
        }),
      ],
    });

    return [branchStep, suppressRemediation, createAccessLoggingBucketStep];
  }

  /** @override */
  protected getRemediationStep(): AutomationStep {
    return new ExecuteAutomationStep(this, 'Remediation', {
      documentName: HardCodedString.of(`AWS-${this.remediationName}`),
      runtimeParameters: HardCodedStringMap.of(this.getRemediationParams()),
    });
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.GrantedPermission = ['READ'];
    params.GranteeType = ['Group'];
    params.GranteeUri = ['http://acs.amazonaws.com/groups/s3/LogDelivery']; //NOSONAR This is the recommended URL for a log delivery group.
    params.TargetPrefix = [StringVariable.of(`ParseInput.${this.resourceIdName}`)];
    params.TargetBucket = [getTargetBucketName(this.solutionId)];

    return params;
  }
}
/* eslint-disable @typescript-eslint/no-unused-vars */
function getTargetBucketName(solutionId: string): IStringVariable {
  //return new StringFormat(`${solutionId}-cloudtrailaccesslogs-%s-%s`.toLowerCase(), [
  return new StringFormat(`cnxc-s3-server-access-logging-%s-%s`.toLowerCase(), [
    StringVariable.of('global:ACCOUNT_ID'),
    StringVariable.of('global:REGION'),
  ]);
}
/* eslint-enable @typescript-eslint/no-unused-vars */
