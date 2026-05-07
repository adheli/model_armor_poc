from unittest.mock import MagicMock, patch

import pytest
from google.cloud.modelarmor_v1 import FilterMatchState, FilterExecutionState
from .model_armor import ModelArmorService, process_filter_results, \
    process_sdp_filter_results


@pytest.fixture
def model_armor_service():
    with patch("google.cloud.modelarmor_v1.ModelArmorClient"):
        service = ModelArmorService(project_id="test-project", location="us-central1", template_id="test-template")
        return service


def test_sanitize_input_no_match(model_armor_service):
    # Mock response
    mock_response = MagicMock()
    mock_response.sanitization_result.filter_match_state = FilterMatchState.NO_MATCH_FOUND
    model_armor_service.client.sanitize_user_prompt.return_value = mock_response

    # Should not raise exception
    model_armor_service.sanitize_input("Safe text")
    model_armor_service.client.sanitize_user_prompt.assert_called_once()


def test_sanitize_input_match_found(model_armor_service):
    # Mock response
    mock_response = MagicMock()
    mock_response.sanitization_result.filter_match_state = FilterMatchState.MATCH_FOUND
    model_armor_service.client.sanitize_user_prompt.return_value = mock_response

    # Should raise ValueError
    with pytest.raises(ValueError, match="Input blocked by Model Armor."):
        model_armor_service.sanitize_input("Unsafe text")


def test_sanitize_output_no_match(model_armor_service):
    # Mock response
    mock_response = MagicMock()
    mock_response.sanitization_result.filter_match_state = FilterMatchState.NO_MATCH_FOUND
    model_armor_service.client.sanitize_model_response.return_value = mock_response

    result = model_armor_service.sanitize_output("Safe output")
    assert result is None


def test_sanitize_output_match_with_redaction(model_armor_service):
    # Mock response
    mock_response = MagicMock()
    mock_response.sanitization_result.filter_match_state = FilterMatchState.MATCH_FOUND

    mock_filter_result = MagicMock()
    # Setup SDP result with redaction
    mock_filter_result.sdp_filter_result.inspect_result.match_state = FilterMatchState.MATCH_FOUND
    mock_filter_result.sdp_filter_result.deidentify_result.execution_state = FilterExecutionState.EXECUTION_SUCCESS
    mock_filter_result.sdp_filter_result.deidentify_result.data = "Redacted text"

    # Other filters are empty
    mock_filter_result.csam_filter_filter_result = None
    mock_filter_result.rai_filter_result = None
    mock_filter_result.malicious_uri_filter_result = None
    mock_filter_result.pi_and_jailbreak_filter_result = None
    mock_filter_result.virus_scan_filter_result = None

    mock_response.sanitization_result.filter_results = {"sdp": mock_filter_result}
    model_armor_service.client.sanitize_model_response.return_value = mock_response

    result = model_armor_service.sanitize_output("Sensitive output")
    assert result == "Redacted text"


def test_process_sdp_filter_results_success():
    mock_sdp_result = MagicMock()
    mock_sdp_result.inspect_result.match_state = FilterMatchState.MATCH_FOUND
    mock_sdp_result.inspect_result.message_items = ["Found email"]
    mock_sdp_result.deidentify_result.execution_state = FilterExecutionState.EXECUTION_SUCCESS
    mock_sdp_result.deidentify_result.data = "[EMAIL]"

    result = process_sdp_filter_results(mock_sdp_result)
    assert result["error_messages"] == ["Found email"]
    assert result["deidentify_result"] == "[EMAIL]"


def test_process_filter_results_with_rai():
    mock_filter_result = MagicMock()
    mock_filter_result.rai_filter_result.message_items = ["Inappropriate content"]
    mock_filter_result.rai_filter_result.match_state = FilterMatchState.MATCH_FOUND
    mock_filter_result.csam_filter_filter_result = None
    mock_filter_result.malicious_uri_filter_result = None
    mock_filter_result.pi_and_jailbreak_filter_result = None
    mock_filter_result.virus_scan_filter_result = None
    mock_filter_result.sdp_filter_result = None

    filter_results = {"rai": mock_filter_result}
    errors, redacted = process_filter_results(filter_results)

    assert "Message blocked by RAI filter." in errors
    assert redacted == ""
