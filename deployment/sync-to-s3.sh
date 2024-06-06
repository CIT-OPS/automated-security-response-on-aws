#!/bin/bash
# Source the setenv.sh file to load the environment variables
# ie:
# export DIST_OUTPUT_BUCKET=sharr-deploy-008012068868
# export DIST_VERSION=v2.1.1.cnxc.1
# export DIST_SOLUTION_NAME=automated-security-response-on-aws
source setenv.sh
# Extract the last 12 characters
ACCOUNT_IDENTIFIER=${DIST_OUTPUT_BUCKET: -12}

CREATE_BUCKETS=0

# Now you can use the environment variables in your script
echo "Output Bucket: $DIST_OUTPUT_BUCKET"
echo "Version: $DIST_VERSION"
echo "Solution Name: $DIST_SOLUTION_NAME"
echo "Account Identifier: $ACCOUNT_IDENTIFIER"

if [ "$ACCOUNT_IDENTIFIER" == "008012068868" ]; then
    #CXTECH KENS LAB
    ORGANIZATION_ID="o-ey4kshnlxl"
    SECHUB_ACCOUNT='211125410042'
    TEST_ACCOUNT='211125410042'
    REGIONS=( "us-east-1" "us-west-2" )
elif [ "$ACCOUNT_IDENTIFIER" == "645520830401" ]; then
    #ANYPASS MPA
    ORGANIZATION_ID="o-juwiwellsh"
    SECHUB_ACCOUNT='217745949876'
    TEST_ACCOUNT='217745949876'
    REGIONS=( "us-east-1" "us-east-2" "sa-east-1" "eu-west-2" "ca-central-1" "us-west-2" )
else
    echo "The last 12 characters do not match."
fi


policy_template="bucket-policy-template.json"


do_cmd () {
    echo "------ EXEC $*"
    $*
    rc=$?
    if [ $rc -gt 0 ]
    then
            echo "Aborted - rc=$rc"
            exit $rc
    fi
}

do_sync() {
    echo "------------------------------------------------------------------------------"
    echo "[Init] Sync $1"
    echo "------------------------------------------------------------------------------"
    do_cmd aws s3 sync ./regional-s3-assets/ s3://$DIST_OUTPUT_BUCKET-$1/$DIST_SOLUTION_NAME/$DIST_VERSION --delete --acl bucket-owner-full-control
}

# Function to create bucket and apply policy
create_bucket_and_apply_policy() {
    region=$1
    ACCOUNT_IDENTIFIER=$2
    ORGANIZATION_ID=$3
    bucket_name="$DIST_OUTPUT_BUCKET-$region"
    
    # Create bucket
    echo "Creating bucket $bucket_name in region $region..."
    if [ "$region" = "us-east-1" ]; then
        aws s3api create-bucket --bucket $bucket_name --region $region
    else
        aws s3api create-bucket --bucket $bucket_name --region $region --create-bucket-configuration LocationConstraint=$region
    fi
    
    # Prepare the policy file
    policy_file="temp/bucket-policy-$region.json"
    sed "s/<account>/$ACCOUNT_IDENTIFIER/g; s/<region>/$region/g; s/<organization>/$ORGANIZATION_ID/g" $policy_template > $policy_file
    
    # Apply bucket policy
    echo "Applying policy to bucket $bucket_name..."
    aws s3api put-bucket-policy --bucket $bucket_name --policy file://$policy_file
}

# Function to create bucket and apply policy
create_refbucket_and_apply_policy() {
    region=$1
    ACCOUNT_IDENTIFIER=$2
    organization=$3
    bucket_name="$DIST_OUTPUT_BUCKET-reference"
    
    # Create bucket
    echo "Creating bucket $bucket_name in region $region..."
    aws s3api create-bucket --bucket $bucket_name --region $region
    
    # Prepare the policy file
    policy_file="temp/bucket-policy-reference.json"
    sed "s/<account>/$ACCOUNT_IDENTIFIER/g; s/<region>/reference/g; s/<organization>/$organization/g" $policy_template > $policy_file
    
    # Apply bucket policy
    echo "Applying policy to bucket $bucket_name..."
    aws s3api put-bucket-policy --bucket $bucket_name --policy file://$policy_file
}


echo "------------------------------------------------------------------------------"
echo "[Init] Sync Global"
echo "------------------------------------------------------------------------------"
echo "------------------------------------------------------------------------------"
echo "lets extracxt all the RELEVANT SSM documents to temp/ssmdocs so you might test deploy one of them"
echo "------------------------------------------------------------------------------"
do_cmd ./extract-ssmdocs.sh

if [ "$CREATE_BUCKETS" == "1" ]; then
    create_refbucket_and_apply_policy 'us-east-1' $ACCOUNT_IDENTIFIER $ORGANIZATION_ID
fi
echo "------------------------------------------------------------------------------"
echo "Our Templates are getting bigger than 100,000 bytes, so we need to minify them"
echo "------------------------------------------------------------------------------"
do_cmd ./minifyTemplates.sh

do_cmd aws s3 sync ./global-s3-assets/ s3://$DIST_OUTPUT_BUCKET-reference/$DIST_SOLUTION_NAME/$DIST_VERSION --delete --acl bucket-owner-full-control

for i in "${REGIONS[@]}"
do
   : 
   if [ "$CREATE_BUCKETS" == "1" ]; then
        echo "------------------------------------------------------------------------------"
        echo "Creating Bucket for account $ACCOUNT_IDENTIFIER in region $i"
        echo "------------------------------------------------------------------------------"
        create_bucket_and_apply_policy $i $ACCOUNT_IDENTIFIER $ORGANIZATION_ID
   fi
        echo "------------------------------------------------------------------------------"
        echo "Syncing Bucket for account $ACCOUNT_IDENTIFIER in region $i"
        echo "------------------------------------------------------------------------------"
        do_sync "$i"
done

# Define the file path
output_file="s3-file-names.txt"
# Get the current date and time
current_datetime=$(date)

echo "------------------------------------------------------------------------------"
echo "Generating AWS CLI Deployment scripts"
echo "------------------------------------------------------------------------------"

# Write three lines to the file
echo "#   AUTOGENERATED FILE - REBUILT WITH sync-to-s3.sh" > $output_file
echo "https://$DIST_OUTPUT_BUCKET-reference.s3.amazonaws.com/$DIST_SOLUTION_NAME/$DIST_VERSION/aws-sharr-deploy.template" >> $output_file
echo "https://$DIST_OUTPUT_BUCKET-reference.s3.amazonaws.com/$DIST_SOLUTION_NAME/$DIST_VERSION/aws-sharr-member.template" >> $output_file
echo "https://$DIST_OUTPUT_BUCKET-reference.s3.amazonaws.com/$DIST_SOLUTION_NAME/$DIST_VERSION/aws-sharr-member-roles.template" >> $output_file
echo "Generated date and time: $current_datetime" >> $output_file

# Define output file
output_file='awscli-update-all-member-stackset.sh'
current_datetime=$(date) 

# Create the output file and add the header
{
    echo "#!/bin/bash"
    echo "# This is an autogenerated file by sync-to-s3.sh"
    echo "# Generated date and time: $current_datetime"
} > $output_file

# Append the AWS CLI command to the output file
cat << EOF >> $output_file
aws cloudformation update-stack-set \
--stack-set-name AWSControlTower-SHARR-Member \
--description "(SO0111) AWS Security Hub Automated Response & Remediation MEMBER Stack, $DIST_SOLUTION_NAME $DIST_VERSION" \
--template-url "https://$DIST_OUTPUT_BUCKET-reference.s3.amazonaws.com/$DIST_SOLUTION_NAME/$DIST_VERSION/aws-sharr-member.template" \
--parameters ParameterKey=CreateS3BucketForRedshiftAuditLogging,UsePreviousValue=true ParameterKey=LoadAFSBPMemberStack,UsePreviousValue=true ParameterKey=LoadCIS120MemberStack,UsePreviousValue=true ParameterKey=LoadCIS140MemberStack,UsePreviousValue=true ParameterKey=LoadNIST80053MemberStack,UsePreviousValue=true ParameterKey=LoadPCI321MemberStack,UsePreviousValue=true ParameterKey=LoadSCMemberStack,UsePreviousValue=true ParameterKey=LogGroupName,UsePreviousValue=true ParameterKey=SecHubAdminAccount,UsePreviousValue=true \
--capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
--tags Key=Solution,Value=$DIST_SOLUTION_NAME Key=Version,Value=$DIST_VERSION Key=App,Value=SHARR \
--operation-preferences FailureToleranceCount=49,MaxConcurrentCount=50,RegionConcurrencyType=PARALLEL \
--administration-role-arn arn:aws:iam::$ACCOUNT_IDENTIFIER:role/service-role/AWSControlTowerStackSetRole \
--execution-role-name AWSControlTowerExecution \
--permission-model SELF_MANAGED \
--call-as SELF 
EOF
chmod +x $output_file

output_file='awscli-update-single-member-stackset.sh'
# Create the output file and add the header
{
    echo "#!/bin/bash"
    echo "# This is an autogenerated file by sync-to-s3.sh"
    echo "# Generated date and time: $current_datetime"
} > $output_file

# Append the AWS CLI command to the output file
cat << EOF >> $output_file
aws cloudformation update-stack-set \
--stack-set-name AWSControlTower-SHARR-Member \
--description "(SO0111) AWS Security Hub Automated Response & Remediation MEMBER Stack, $DIST_SOLUTION_NAME $DIST_VERSION" \
--template-url "https://$DIST_OUTPUT_BUCKET-reference.s3.amazonaws.com/$DIST_SOLUTION_NAME/$DIST_VERSION/aws-sharr-member.template" \
--parameters ParameterKey=CreateS3BucketForRedshiftAuditLogging,UsePreviousValue=true ParameterKey=LoadAFSBPMemberStack,UsePreviousValue=true ParameterKey=LoadCIS120MemberStack,UsePreviousValue=true ParameterKey=LoadCIS140MemberStack,UsePreviousValue=true ParameterKey=LoadNIST80053MemberStack,UsePreviousValue=true ParameterKey=LoadPCI321MemberStack,UsePreviousValue=true ParameterKey=LoadSCMemberStack,UsePreviousValue=true ParameterKey=LogGroupName,UsePreviousValue=true ParameterKey=SecHubAdminAccount,UsePreviousValue=true \
--capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
--tags Key=Solution,Value=$DIST_SOLUTION_NAME Key=Version,Value=$DIST_VERSION Key=App,Value=SHARR \
--operation-preferences FailureToleranceCount=49,MaxConcurrentCount=50,RegionConcurrencyType=PARALLEL \
--administration-role-arn arn:aws:iam::$ACCOUNT_IDENTIFIER:role/service-role/AWSControlTowerStackSetRole \
--execution-role-name AWSControlTowerExecution \
--permission-model SELF_MANAGED \
--call-as SELF \
--accounts $TEST_ACCOUNT \
--regions ${REGIONS[@]}
EOF
chmod +x $output_file

# Define output file
output_file='awscli-update-all-member-roles.sh'
current_datetime=$(date) 

# Create the output file and add the header
{
    echo "#!/bin/bash"
    echo "# This is an autogenerated file by sync-to-s3.sh"
    echo "# Generated date and time: $current_datetime"
} > $output_file

# Append the AWS CLI command to the output file
cat << EOF >> $output_file
aws cloudformation update-stack-set \
--stack-set-name AWSControlTower-SHARR-MemberRoles \
--description "(SO0111) AWS Security Hub Automated Response & Remediation ROLES Stack, $DIST_SOLUTION_NAME $DIST_VERSION" \
--template-url "https://$DIST_OUTPUT_BUCKET-reference.s3.amazonaws.com/$DIST_SOLUTION_NAME/$DIST_VERSION/aws-sharr-member-roles.template" \
--parameters ParameterKey=SecHubAdminAccount,UsePreviousValue=true \
--capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
--tags Key=Solution,Value=$DIST_SOLUTION_NAME Key=Version,Value=$DIST_VERSION Key=App,Value=SHARR \
--operation-preferences FailureToleranceCount=49,MaxConcurrentCount=50,RegionConcurrencyType=PARALLEL \
--permission-model SERVICE_MANAGED \
--call-as SELF 
EOF
chmod +x $output_file

output_file='awscli-update-admin-stackset.sh'
# Create the output file and add the header
{
    echo "#!/bin/bash"
    echo "# This is an autogenerated file by sync-to-s3.sh"
    echo "# Generated date and time: $current_datetime"
} > $output_file

# Append the AWS CLI command to the output file
cat << EOF >> $output_file
aws cloudformation update-stack-set \
--stack-set-name AWSControlTower-SHARR-Admin \
--description "(SO0111) AWS Security Hub Automated Response & Remediation ADMINISTRATOR Stack, $DIST_SOLUTION_NAME $DIST_VERSION" \
--template-url "https://$DIST_OUTPUT_BUCKET-reference.s3.amazonaws.com/$DIST_SOLUTION_NAME/$DIST_VERSION/aws-sharr-deploy.template" \
--parameters ParameterKey=LoadAFSBPAdminStack,UsePreviousValue=false,ParameterValue=no ParameterKey=LoadCIS120AdminStack,UsePreviousValue=false,ParameterValue=no ParameterKey=LoadCIS140AdminStack,UsePreviousValue=false,ParameterValue=no ParameterKey=LoadNIST80053AdminStack,UsePreviousValue=false,ParameterValue=no ParameterKey=LoadPCI321AdminStack,UsePreviousValue=false,ParameterValue=no ParameterKey=LoadSCAdminStack,UsePreviousValue=false,ParameterValue=yes ParameterKey=ReuseOrchestratorLogGroup,UsePreviousValue=false,ParameterValue=yes ParameterKey=StateMachineExecutionsAlarmThreshold,UsePreviousValue=false,ParameterValue=1000 ParameterKey=UseCloudWatchMetrics,UsePreviousValue=false,ParameterValue=yes ParameterKey=UseCloudWatchMetricsAlarms,UsePreviousValue=false,ParameterValue=yes \
--capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
--tags Key=Solution,Value=$DIST_SOLUTION_NAME Key=Version,Value=$DIST_VERSION Key=App,Value=SHARR \
--operation-preferences FailureToleranceCount=49,MaxConcurrentCount=50,RegionConcurrencyType=PARALLEL \
--administration-role-arn arn:aws:iam::$ACCOUNT_IDENTIFIER:role/service-role/AWSControlTowerStackSetRole \
--execution-role-name AWSControlTowerExecution \
--permission-model SELF_MANAGED \
--call-as SELF \
--accounts $SECHUB_ACCOUNT \
--regions us-east-1
EOF
chmod +x $output_file

# Print a message to indicate the task is done
cat $output_file

echo Upload to S3 Complete
