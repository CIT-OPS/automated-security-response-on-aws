// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { IControl } from '../../../lib/sharrplaybook-construct';
import { compareVersions } from 'compare-versions';

// Creates one rule per control Id. The Step Function determines what document to run based on
// Security Standard and Control Id. See cis-member-stack
// versionAdded is set to 2.1.0 for all remediations added up to that release
const remediations: IControl[] = [
  { control: 'Athena.4', versionAdded: '2.2.0' },
  { control: 'APIGateway.1', versionAdded: '2.1.0' }, // CNXC API Gateway REST and WebSocket API execution logging should be enabled
  { control: 'APIGateway.3', executes: 'APIGateway.1', versionAdded: '2.1.0' }, // CNXC Remediation added in <2.1.0
  { control: 'APIGateway.4', versionAdded: '2.1.0' }, // CNXC Remediation added in <2.1.0
  { control: 'APIGateway.5', versionAdded: '2.2.0' },
  { control: 'AutoScaling.1', versionAdded: '2.1.0' },
  { control: 'AutoScaling.3', versionAdded: '2.2.0' },
  { control: 'Autoscaling.5', versionAdded: '2.2.0' },
  { control: 'CloudFormation.1', versionAdded: '2.1.0' },
  { control: 'CloudFront.1', versionAdded: '2.1.0' },
  { control: 'CloudFront.3', executes: 'CloudFront.1', versionAdded: '2.1.0' }, // CNXC Remediation added in <2.1.0
  { control: 'CloudFront.5', executes: 'CloudFront.1', versionAdded: '2.1.0' }, // CNXC Remediation added in <2.1.0
  { control: 'CloudFront.12', versionAdded: '2.1.0' },
  { control: 'CloudTrail.1', versionAdded: '2.1.0' },
  { control: 'CloudTrail.2', versionAdded: '2.1.0' },
  { control: 'CloudTrail.3', executes: 'CloudTrail.1', versionAdded: '2.1.0' },
  { control: 'CloudTrail.4', versionAdded: '2.1.0' },
  { control: 'CloudTrail.5', versionAdded: '2.1.0' },
  { control: 'CloudTrail.6', versionAdded: '2.1.0' },
  { control: 'CloudTrail.7', versionAdded: '2.1.0' },
  { control: 'CloudWatch.1', versionAdded: '2.1.0' },
  { control: 'CloudWatch.2', executes: 'CloudWatch.1', versionAdded: '2.1.0' },
  { control: 'CloudWatch.3', executes: 'CloudWatch.1', versionAdded: '2.1.0' },
  { control: 'CloudWatch.4', executes: 'CloudWatch.1', versionAdded: '2.1.0' },
  { control: 'CloudWatch.5', executes: 'CloudWatch.1', versionAdded: '2.1.0' },
  { control: 'CloudWatch.6', executes: 'CloudWatch.1', versionAdded: '2.1.0' },
  { control: 'CloudWatch.7', executes: 'CloudWatch.1', versionAdded: '2.1.0' },
  { control: 'CloudWatch.8', executes: 'CloudWatch.1', versionAdded: '2.1.0' },
  { control: 'CloudWatch.9', executes: 'CloudWatch.1', versionAdded: '2.1.0' },
  { control: 'CloudWatch.10', executes: 'CloudWatch.1', versionAdded: '2.1.0' },
  { control: 'CloudWatch.11', executes: 'CloudWatch.1', versionAdded: '2.1.0' },
  { control: 'CloudWatch.12', executes: 'CloudWatch.1', versionAdded: '2.1.0' },
  { control: 'CloudWatch.13', executes: 'CloudWatch.1', versionAdded: '2.1.0' },
  { control: 'CloudWatch.14', executes: 'CloudWatch.1', versionAdded: '2.1.0' },
  { control: 'CloudWatch.16', versionAdded: '2.2.0' },
  { control: 'CodeBuild.2', versionAdded: '2.1.0' },
  { control: 'CodeBuild.5', versionAdded: '2.1.0' },
  { control: 'Config.1', versionAdded: '2.1.0' },
  { control: 'EC2.1', versionAdded: '2.1.0' },
  { control: 'EC2.2', versionAdded: '2.1.0' },
  { control: 'EC2.4', versionAdded: '2.1.0' },
  { control: 'EC2.6', versionAdded: '2.1.0' },
  { control: 'EC2.7', versionAdded: '2.1.0' },
  { control: 'EC2.8', versionAdded: '2.1.0' },
  { control: 'EC2.10', versionAdded: '2.2.0' },
  { control: 'EC2.13', versionAdded: '2.1.0' },
  { control: 'EC2.14', executes: 'EC2.13', versionAdded: '2.1.0' },
  { control: 'EC2.15', versionAdded: '2.1.0' },
  { control: 'EC2.18', versionAdded: '2.1.0' },
  { control: 'EC2.19', versionAdded: '2.1.0' },
  { control: 'EC2.23', versionAdded: '2.1.0' },
  { control: 'IAM.3', versionAdded: '2.1.0' },
  { control: 'IAM.7', versionAdded: '2.1.0' },
  { control: 'IAM.8', versionAdded: '2.1.0' },
  { control: 'IAM.11', executes: 'IAM.7', versionAdded: '2.1.0' },
  { control: 'IAM.12', executes: 'IAM.7', versionAdded: '2.1.0' },
  { control: 'IAM.13', executes: 'IAM.7', versionAdded: '2.1.0' },
  { control: 'IAM.14', executes: 'IAM.7', versionAdded: '2.1.0' },
  { control: 'IAM.15', executes: 'IAM.7', versionAdded: '2.1.0' },
  { control: 'IAM.16', executes: 'IAM.7', versionAdded: '2.1.0' },
  { control: 'IAM.17', executes: 'IAM.7', versionAdded: '2.1.0' },
  { control: 'IAM.18', versionAdded: '2.1.0' },
  { control: 'IAM.22', versionAdded: '2.1.0' },
  { control: 'KMS.4', versionAdded: '2.1.0' },
  { control: 'Lambda.1', versionAdded: '2.1.0' },
  { control: 'RDS.1', versionAdded: '2.1.0' },
  { control: 'RDS.2', versionAdded: '2.1.0' },
  { control: 'RDS.4', versionAdded: '2.1.0' },
  { control: 'RDS.5', versionAdded: '2.1.0' },
  { control: 'RDS.6', versionAdded: '2.1.0' },
  { control: 'RDS.7', versionAdded: '2.1.0' },
  { control: 'RDS.8', versionAdded: '2.1.0' },
  { control: 'RDS.13', versionAdded: '2.1.0' },
  { control: 'RDS.16', versionAdded: '2.1.0' },
  { control: 'Redshift.1', versionAdded: '2.1.0' },
  { control: 'Redshift.3', versionAdded: '2.1.0' },
  { control: 'Redshift.4', versionAdded: '2.1.0' },
  { control: 'Redshift.6', versionAdded: '2.1.0' },
  { control: 'S3.1', versionAdded: '2.1.0' },
  { control: 'S3.2', versionAdded: '2.1.0' },
  { control: 'S3.3', executes: 'S3.2', versionAdded: '2.1.0' },
  { control: 'S3.4', versionAdded: '2.1.0' },
  { control: 'S3.5', versionAdded: '2.1.0' },
  { control: 'S3.6', versionAdded: '2.1.0' },
  { control: 'S3.8', executes: 'S3.2', versionAdded: '2.1.0' },
  // { control: 'S3.9', executes: 'CloudTrail.7', versionAdded: '2.1.0' }, DONT USE AWS VERSION
  { control: 'S3.11', versionAdded: '2.1.0' },
  { control: 'S3.13', versionAdded: '2.1.0' },
  { control: 'SecretsManager.1', versionAdded: '2.1.0' },
  { control: 'SecretsManager.3', versionAdded: '2.1.0' },
  { control: 'SecretsManager.4', versionAdded: '2.1.0' },
  { control: 'SNS.1', versionAdded: '2.1.0' },
  { control: 'SQS.1', versionAdded: '2.1.0' },
  { control: 'SSM.1', versionAdded: '2.2.0' },
  { control: 'SSM.4', versionAdded: '2.1.0' },
  { control: 'GuardDuty.1', versionAdded: '2.1.0' },
  { control: 'GuardDuty.2', versionAdded: '2.2.0' },
  { control: 'GuardDuty.4', executes: 'GuardDuty.2', versionAdded: '2.2.0' },
  { control: 'Macie.1', versionAdded: '2.2.0' },
  { control: 'DynamoDB.2', versionAdded: '2.1.0' }, // CNXC DynamoDB tables should have point-in-time recovery enabled
  { control: 'DynamoDB.6', versionAdded: '2.1.0' }, // CNXC DynamoDB tables should have deletion protection enabled
  { control: 'ELB.5', versionAdded: '2.1.0' }, // CNXC Remediation added in <2.1.0
  { control: 'S3.9', versionAdded: '2.1.0' }, // CNXC Remediation added in 2.1.0
  { control: 'StepFunctions.1', versionAdded: '2.1.0' }, // CNXC Remediation added in 2.1.0
];
export const SC_REMEDIATIONS: IControl[] = [...remediations].sort((controlA, controlB) =>
  compareVersions(controlA.versionAdded, controlB.versionAdded),
);
