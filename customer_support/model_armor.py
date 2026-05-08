from typing import MutableMapping

from google.api_core.client_options import ClientOptions
from google.cloud import modelarmor_v1
from google.cloud.modelarmor_v1 import FilterMatchState, SdpFilterResult, FilterResult, FilterExecutionState, \
    SanitizeModelResponseResponse


class ModelArmorService:
    """Service for sanitizing input and output using Google Cloud Model Armor."""

    def __init__(self, project_id: str, location: str, template_id: str):
        """Initializes the Model Armor service with project, location, and template details."""
        self.template = f"projects/{project_id}/locations/{location}/templates/{template_id}"
        self.client = modelarmor_v1.ModelArmorClient(
            transport="rest",
            client_options=ClientOptions(api_endpoint=f"modelarmor.{location}.rep.googleapis.com"),
        )

    def sanitize_input(self, text: str):
        """Sanitizes the user input text using Model Armor."""
        input_text = {"text": text}
        user_prompt_data = modelarmor_v1.DataItem(input_text)

        request_item = {"name": self.template, "user_prompt_data": user_prompt_data}
        request = modelarmor_v1.SanitizeUserPromptRequest(request_item)

        response = self.client.sanitize_user_prompt(request=request)
        print(f"Prompt Sanitizing - Model Armor response: {response}")

        if response.sanitization_result:
            if response.sanitization_result.filter_match_state == FilterMatchState.MATCH_FOUND:
                raise ValueError("Input blocked by Model Armor.")

    def sanitize_output(self, text: str):
        """Sanitizes the model response text using Model Armor."""
        response = self.check_for_sanitizing_flag(text)

        if response.sanitization_result:
            if response.sanitization_result.filter_match_state == FilterMatchState.MATCH_FOUND:
                redacted_text = sanitize_sensitive_data(response)
                if redacted_text:
                    return redacted_text
                else:
                    errors = process_filter_results(response.sanitization_result.filter_results)
                    raise ValueError(f"Model response blocked by Model Armor. Errors: {errors}")

        print("No issues found.")
        return None

    def check_for_sanitizing_flag(self, text: str) -> SanitizeModelResponseResponse:
        data_item = {"text": text}
        model_response_data = modelarmor_v1.DataItem(data_item)

        request_item = {"name": self.template, "model_response_data": model_response_data}
        request = modelarmor_v1.SanitizeModelResponseRequest(request_item)

        response = self.client.sanitize_model_response(request=request)
        return response


def sanitize_sensitive_data(response: SanitizeModelResponseResponse):
    """Sanitizes sensitive data using Model Armor."""
    if response.sanitization_result.filter_results:
        sdp_filter_result_item = response.sanitization_result.filter_results.get("sdpFilterResult")
        if sdp_filter_result_item:
            errors, redacted_text = process_sdp_filter_results(sdp_filter_result_item.sdp_filter_result)
            print(f"Sensitive data filtered. Issues found: {errors}")
            return redacted_text

    return None


def process_filter_results(filter_result: MutableMapping[str, FilterResult]):
    """Processes filter results from Model Armor.

    Args:
        filter_result: A mapping of filter names to their results.

    Returns:
        list: A list of filter errors.
    """
    filter_errors = []

    for _, filter_item in filter_result.items():
        if (filter_item.csam_filter_filter_result and
                filter_item.csam_filter_filter_result.match_state == FilterMatchState.MATCH_FOUND):
            filter_errors.append("Message blocked by CSAM filter.")

        if filter_item.rai_filter_result and filter_item.rai_filter_result.match_state == FilterMatchState.MATCH_FOUND:
            filter_errors.append("Message blocked by RAI filter.")

        if filter_item.malicious_uri_filter_result and filter_item.malicious_uri_filter_result.match_state == FilterMatchState.MATCH_FOUND:
            filter_errors.append("Message blocked as it contains malicious URLs.")

        if filter_item.pi_and_jailbreak_filter_result and filter_item.pi_and_jailbreak_filter_result.match_state == FilterMatchState.MATCH_FOUND:
            filter_errors.append("Message blocked for potential phishing attacks.")

        if filter_item.virus_scan_filter_result and filter_item.virus_scan_filter_result.match_state == FilterMatchState.MATCH_FOUND:
            filter_errors.append("Message might be infected with a virus.")

    return filter_errors


def process_sdp_filter_results(sdp_result: SdpFilterResult):
    """Processes sensitive data protection (SDP) filter results.

    Args:
        sdp_result: The SDP filter result from Model Armor.

    Returns:
        tuple: A tuple containing a list of error messages and the de-identified result.
    """
    errors=[]
    deidentify_result = None

    if sdp_result:
        if sdp_result.inspect_result.match_state == FilterMatchState.MATCH_FOUND:
            print(f"Sensitive data found")
            errors = sdp_result.inspect_result.message_items

        if (sdp_result.deidentify_result
                and sdp_result.deidentify_result.execution_state == FilterExecutionState.EXECUTION_SUCCESS):
            deidentify_result = sdp_result.deidentify_result.data

    return errors, deidentify_result
