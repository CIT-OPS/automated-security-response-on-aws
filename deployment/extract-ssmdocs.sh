#!/bin/bash
# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "jq command could not be found. Please install jq."
    exit 1
fi

# Array of CloudFormation template paths
TEMPLATE_PATHS=("global-s3-assets/aws-sharr-remediations.template" "global-s3-assets/playbooks/SCMemberStack.template")

# Create the ssmdocs directory if it doesn't exist
OUTPUT_DIR="temp/ssmdocs"
mkdir -p "$OUTPUT_DIR"

# Loop through each template file
for TEMPLATE_PATH in "${TEMPLATE_PATHS[@]}"; do
    # Check if the template file exists
    if [ ! -f "$TEMPLATE_PATH" ]; then
        echo "CloudFormation template file $TEMPLATE_PATH not found!"
        continue
    fi

    # Extract SSM Document resources from the CloudFormation template
    SSM_DOCS=$(jq -r '.Resources | to_entries[] | select(.value.Type == "AWS::SSM::Document") | .key' "$TEMPLATE_PATH")

    # Loop through each SSM Document resource
    for RESOURCE in $SSM_DOCS; do
        # Get the name of the SSM Document
        NAME=$(jq -r ".Resources[\"$RESOURCE\"].Properties.Name" "$TEMPLATE_PATH")

        # Get the content of the SSM Document
        CONTENT=$(jq -r ".Resources[\"$RESOURCE\"].Properties.Content" "$TEMPLATE_PATH")

        # Write the content to a file named after the SSM Document's Name property in the ssmdocs directory
        echo "$CONTENT" > "$OUTPUT_DIR/${NAME}.json"

        echo "Written content of $RESOURCE from $TEMPLATE_PATH to $OUTPUT_DIR/${NAME}.json"
    done
done

echo "Script completed."