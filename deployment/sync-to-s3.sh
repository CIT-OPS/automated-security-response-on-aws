#!/bin/bash
# Functions to reduce repetitive code
# do_cmd will exit if the command has a non-zero return code.
release='v2.0.2.cnxc.2'

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
    do_cmd aws s3 sync ./regional-s3-assets/ s3://sharr-deploy-$1/aws-security-hub-automated-response-and-remediation/$release --delete --acl bucket-owner-full-control
}


echo "------------------------------------------------------------------------------"
echo "[Init] Sync Global"
echo "------------------------------------------------------------------------------"
do_cmd aws s3 sync ./global-s3-assets/ s3://sharr-deploy-reference/aws-security-hub-automated-response-and-remediation/$release --delete --acl bucket-owner-full-control

regions=( "us-east-1" "us-east-2" "us-west-1" "us-west-2" "ap-southeast-2" "ca-central-1" "eu-west-2" "ap-southeast-1")
for i in "${regions[@]}"
do
   : 
   do_sync "$i"
done


echo Upload to S3 Complete
