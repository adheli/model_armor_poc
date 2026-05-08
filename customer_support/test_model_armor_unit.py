from unittest.mock import MagicMock, patch

import pytest
from google.cloud.modelarmor_v1 import FilterMatchState, FilterExecutionState, SdpFilterResult
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

    # Setup SDP result with redaction
    mock_sdp_filter_result = MagicMock()
    mock_sdp_filter_result.inspect_result.match_state = FilterMatchState.MATCH_FOUND
    mock_sdp_filter_result.deidentify_result.execution_state = FilterExecutionState.EXECUTION_SUCCESS
    mock_sdp_filter_result.deidentify_result.data = "Redacted text"

    mock_filter_item = MagicMock()
    mock_filter_item.sdp_filter_result = mock_sdp_filter_result

    # Other filters are empty
    mock_filter_item.csam_filter_filter_result = None
    mock_filter_item.rai_filter_result = None
    mock_filter_item.malicious_uri_filter_result = None
    mock_filter_item.pi_and_jailbreak_filter_result = None
    mock_filter_item.virus_scan_filter_result = None

    mock_response.sanitization_result.filter_results = {"sdpFilterResult": mock_filter_item}
    model_armor_service.client.sanitize_model_response.return_value = mock_response

    result = model_armor_service.sanitize_output("Sensitive output")
    assert result == "Redacted text"


def test_process_sdp_filter_results_success():
    mock_sdp_result = MagicMock()
    mock_sdp_result.inspect_result.match_state = FilterMatchState.MATCH_FOUND
    mock_sdp_result.inspect_result.message_items = ["Found email"]
    mock_sdp_result.deidentify_result.execution_state = FilterExecutionState.EXECUTION_SUCCESS
    mock_sdp_result.deidentify_result.data = "[EMAIL]"

    errors, redacted_text = process_sdp_filter_results(mock_sdp_result)
    assert errors == ["Found email"]
    assert redacted_text == "[EMAIL]"


def test_sanitize_output_match_found_no_redaction(model_armor_service):
    # Mock response
    mock_response = MagicMock()
    mock_response.sanitization_result.filter_match_state = FilterMatchState.MATCH_FOUND
    mock_response.sanitization_result.filter_results = {"rai": MagicMock()}
    mock_response.sanitization_result.filter_results["rai"].rai_filter_result.match_state = FilterMatchState.MATCH_FOUND
    mock_response.sanitization_result.filter_results["rai"].csam_filter_filter_result = None
    mock_response.sanitization_result.filter_results["rai"].malicious_uri_filter_result = None
    mock_response.sanitization_result.filter_results["rai"].pi_and_jailbreak_filter_result = None
    mock_response.sanitization_result.filter_results["rai"].virus_scan_filter_result = None

    model_armor_service.client.sanitize_model_response.return_value = mock_response

    # Should raise ValueError because match found but no redaction (SDP) happened
    with pytest.raises(ValueError, match="Model response blocked by Model Armor. Errors:"):
        model_armor_service.sanitize_output("Unsafe output")


def test_check_for_sanitizing_flag(model_armor_service):
    mock_response = MagicMock()
    model_armor_service.client.sanitize_model_response.return_value = mock_response

    result = model_armor_service.check_for_sanitizing_flag("Some text")
    assert result == mock_response
    model_armor_service.client.sanitize_model_response.assert_called_once()

def test_process_filter_results_with_rai():
    mock_filter_item = MagicMock()
    mock_filter_item.rai_filter_result.match_state = FilterMatchState.MATCH_FOUND
    mock_filter_item.csam_filter_filter_result = None
    mock_filter_item.malicious_uri_filter_result = None
    mock_filter_item.pi_and_jailbreak_filter_result = None
    mock_filter_item.virus_scan_filter_result = None

    filter_results = {"rai_filter": mock_filter_item}
    errors = process_filter_results(filter_results)

    assert "Message blocked by RAI filter." in errors
