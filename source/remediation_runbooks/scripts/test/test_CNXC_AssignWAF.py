import unittest
from unittest.mock import MagicMock, patch

# Import the module to test
import CNXC_AssignWAF as script
from botocore.exceptions import ClientError

# Add this at the module level
responses = {"AssociateWAFResponse": []}


class TestCNXCAssignWAF(unittest.TestCase):

    def setUp(self):
        # Clear responses before each test
        responses["AssociateWAFResponse"] = []

    @patch("boto3.client")
    def test_connect_to_wafv2(self, mock_boto_client):
        mock_config = MagicMock()
        script.connect_to_wafv2(mock_config)
        mock_boto_client.assert_called_once_with("wafv2", config=mock_config)

    @patch("boto3.client")
    def test_get_account(self, mock_boto_client):
        mock_sts = MagicMock()
        mock_boto_client.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

        mock_config = MagicMock()
        result = script.get_account(mock_config)

        self.assertEqual(result, "123456789012")
        mock_boto_client.assert_called_once_with("sts", config=mock_config)

    @patch("CNXC_AssignWAF.connect_to_wafv2")  # Changed from scripts.CNXC_AssignWAF
    def test_associate_wafv2_with_apigateway_success(self, mock_connect):
        mock_wafv2_client = MagicMock()
        mock_connect.return_value = mock_wafv2_client

        resource_id = "arn:aws:apigateway:us-east-1::/restapis/abc123/stages/prod"
        web_acl_arn = (
            "arn:aws:wafv2:us-east-1:123456789012:global/webacl/test-waf/abcdef"
        )

        result = script.associate_wafv2_with_apigateway(resource_id, web_acl_arn)

        self.assertEqual(result, "OK")
        mock_wafv2_client.associate_web_acl.assert_called_once_with(
            ResourceArn=resource_id, WebACLArn=web_acl_arn
        )

    @patch(
        "CNXC_AssignWAF.associate_wafv2_with_apigateway"
    )  # Changed from scripts.CNXC_AssignWAF
    def test_runbook_handler(self, mock_associate):
        mock_associate.return_value = "OK"

        event = {
            "ResourceId": "arn:aws:apigateway:us-east-1::/restapis/abc123/stages/prod",
            "WAF_ARN": "arn:aws:wafv2:us-east-1:123456789012:global/webacl/test-waf/abcdef",
        }
        context = {}

        result = script.runbook_handler(event, context)

        expected_response = {
            "output": "Associate Response",
            "http_responses": {
                "AssociateWAFResponse": [
                    {
                        "Action": f"Associating {event['ResourceId']} with WAF {event['WAF_ARN']}",
                        "Message": "OK",
                    }
                ]
            },
        }

        self.assertEqual(result, expected_response)
        mock_associate.assert_called_once_with(event["ResourceId"], event["WAF_ARN"])

    @patch("CNXC_AssignWAF.connect_to_wafv2")  # Changed from scripts.CNXC_AssignWAF
    def test_associate_wafv2_with_apigateway_error(self, mock_connect):
        mock_wafv2_client = MagicMock()
        mock_connect.return_value = mock_wafv2_client

        error_response = {
            "Error": {
                "Code": "WAFUnavailableEntityException",
                "Message": "The specified entity is not available",
            }
        }
        mock_wafv2_client.associate_web_acl.side_effect = ClientError(
            error_response, "AssociateWebACL"
        )

        resource_id = "arn:aws:apigateway:us-east-1::/restapis/abc123/stages/prod"
        web_acl_arn = (
            "arn:aws:wafv2:us-east-1:123456789012:global/webacl/test-waf/abcdef"
        )

        with self.assertRaises(ClientError):
            script.associate_wafv2_with_apigateway(resource_id, web_acl_arn)


if __name__ == "__main__":
    unittest.main()
