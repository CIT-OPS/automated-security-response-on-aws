#!/bin/bash
# This is an autogenerated file by sync-to-s3.sh
# Generated date and time: Mon Jul 22 12:26:48 EDT 2024
aws cloudformation update-stack-set --stack-set-name AWSControlTower-SHARR-Admin --description "(SO0111) AWS Security Hub Automated Response & Remediation ADMINISTRATOR Stack, automated-security-response-on-aws v2.1.2.cnxc.1" --template-url "https://sharr-deploy-194039877044-reference.s3.amazonaws.com/automated-security-response-on-aws/v2.1.2.cnxc.1/aws-sharr-deploy.template" --parameters ParameterKey=LoadAFSBPAdminStack,UsePreviousValue=false,ParameterValue=no ParameterKey=LoadCIS120AdminStack,UsePreviousValue=false,ParameterValue=no ParameterKey=LoadCIS140AdminStack,UsePreviousValue=false,ParameterValue=no ParameterKey=LoadNIST80053AdminStack,UsePreviousValue=false,ParameterValue=no ParameterKey=LoadPCI321AdminStack,UsePreviousValue=false,ParameterValue=no ParameterKey=LoadSCAdminStack,UsePreviousValue=false,ParameterValue=yes ParameterKey=ReuseOrchestratorLogGroup,UsePreviousValue=false,ParameterValue=yes ParameterKey=StateMachineExecutionsAlarmThreshold,UsePreviousValue=false,ParameterValue=1000 ParameterKey=UseCloudWatchMetrics,UsePreviousValue=false,ParameterValue=yes ParameterKey=UseCloudWatchMetricsAlarms,UsePreviousValue=false,ParameterValue=yes --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND --tags Key=Solution,Value=automated-security-response-on-aws Key=Version,Value=v2.1.2.cnxc.1 Key=App,Value=SHARR --operation-preferences FailureToleranceCount=49,MaxConcurrentCount=50,RegionConcurrencyType=PARALLEL --administration-role-arn arn:aws:iam::194039877044:role/service-role/AWSControlTowerStackSetRole --execution-role-name AWSControlTowerExecution --permission-model SELF_MANAGED --call-as SELF --accounts 332241576022 --regions us-east-1