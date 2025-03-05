#!/bin/bash

# Replace the following variables with your actual values
STACK_SET_NAME="AWSControlTower-SHARR-Member-v150-cnxc"
REGIONS=("us-east-1" "us-west-2" "ca-central-1" "eu-west-2" "ap-southeast-2" "us-east-2" "us-west-2")

# Step 1: List all active accounts in the organization
active_accounts=$(aws organizations list-accounts --query 'Accounts[?Status==`ACTIVE`].Id' --output text)
#active_accounts=("736200207130")

# Step 2: Delete stack instances for each active account in specified regions
for account_id in "${active_accounts[@]}"; do
    echo "Deleting stack instances for Account: $account_id"
    aws cloudformation delete-stack-instances --stack-set-name $STACK_SET_NAME --accounts '["707411179352", "977959890219", "480098044246", "297117725213", "962508235171", "487046262841", "727982640590", "136105091673", "663673773945", "441039221205", "970276046860", "529247589681", "674845167400", "139701943265", "060326854818", "979311660651", "368022279450", "611146248485", "078762791986", "530637188125", "682727092140", "443585164759", "673423585932", "857932575317", "559493019793", "013627187694", "365251574459", "344895171782", "321066437616", "816177219606", "743667690398", "619391186421", "149755621053", "455768319323", "736200207130", "924746602103", "512429602839", "273377666917", "684153604285", "429302170673", "194039877044", "101437485338", "271153886381", "504414357935", "802214760415", "116418202526", "685686361092", "365207167536", "877724245970", "383037183653", "041471156989", "095124703148", "936709053360", "552229905086", "234772128127", "685949596697", "094630247482", "341481277192", "851471901416", "322995242092", "988338523925", "036371397623", "836733402421", "332241576022", "877937276455", "250722453155", "810239954663", "513600786624", "153866737165", "354924165552", "720815557959", "330945905504", "550082110842", "520495932890", "054621573074", "721472125801", "177958276749", "617678709456", "993454255057", "706806570371", "055138633701", "957902552811", "713399976267", "824069044107", "577484336341", "138778946381", "469310072502", "374583452618", "815549581251", "458091232179"]' --regions '["us-east-1", "us-east-2", "ca-central-1", "eu-west-2", "ap-southeast-2", "us-west-1", "us-west-2"]' --operation-preferences FailureToleranceCount=0,MaxConcurrentCount=1 --no-retain-stacks 
    # aws cloudformation delete-stack-instances \
    #     --stack-set-name $STACK_SET_NAME \
    #     --accounts $account \
    #     --regions $region
done
