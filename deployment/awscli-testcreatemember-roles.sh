#!/bin/bash
# This is an autogenerated file by sync-to-s3.sh
# Generated date and time: Tue Mar  4 22:24:49 EST 2025    41145089
aws cloudformation create-stack \
--capabilities CAPABILITY_NAMED_IAM \
--stack-name ASR-Member-Roles-1741145089 \
--description "(SO0111) AWS Security Hub Automated Response & Remediation ROLES Stack, automated-security-response-on-aws v2.2.0.cnxc.7" \
--template-url "https://sharr-deploy-008012068868-reference.s3.amazonaws.com/automated-security-response-on-aws/v2.2.0.cnxc.7/aws-sharr-member-roles.template" \
--parameters \
  ParameterKey=Namespace,ParameterValue=41145089 \
  ParameterKey=SecHubAdminAccount,ParameterValue=211125410042
