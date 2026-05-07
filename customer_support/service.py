import os
from typing import Optional

import google.auth
from dotenv import load_dotenv
from google.adk.agents.callback_context import CallbackContext
from google.adk.models import LlmRequest, LlmResponse
from google.genai import types
from .model_armor import ModelArmorService

load_dotenv()

PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT")
LOCATION = os.environ.get("GOOGLE_CLOUD_LOCATION")
TEMPLATE_ID = os.environ.get("GOOGLE_CLOUD_TEMPLATE_ID")

credentials, project_id = google.auth.default()
armor = ModelArmorService(project_id, LOCATION, TEMPLATE_ID)


def before_model_callback_handler(callback_context: CallbackContext, llm_request: LlmRequest) -> Optional[LlmResponse]:
    """Callback handler executed before the LLM call.

    Sanitizes user input and can modify the LLM request or return a predefined response.

    Args:
        callback_context: The context of the callback.
        llm_request: The request to be sent to the LLM.

    Returns:
        Optional[LlmResponse]: A response to return instead of calling the LLM, or None to continue.
    """
    print("before_model_callback_handler by agent: " + callback_context.agent_name)

    if llm_request.contents and llm_request.contents[-1].role == "user":
        print("User message detected")

        if llm_request.contents[-1].parts:
            parts = llm_request.contents[-1].parts
            if parts[0] and parts[0].text:
                try:
                    print("Pre-sanitizing input: " + parts[0].text)
                    armor.sanitize_input(parts[0].text)
                    return None

                except (ValueError, TypeError) as e:
                    print(f"Error sanitizing input: {e}")
                    return LlmResponse(content=types.Content(
                        role="model",
                        parts=[types.Part(text="Your request cannot be processed." + e.__str__())],
                    ))
    return None


def after_model_callback_handler(callback_context: CallbackContext, llm_response: LlmResponse) -> Optional[LlmResponse]:
    """Callback handler executed after the LLM call.

    Sanitizes the LLM response before returning it to the user.

    Args:
        callback_context: The context of the callback.
        llm_response: The response from the LLM.

    Returns:
        Optional[LlmResponse]: The sanitized response or a modified response if blocked.
    """
    print("after_model_callback_handler by agent: " + callback_context.agent_name)

    if llm_response.content and llm_response.content.parts:
        if llm_response.content.parts[0].text:
            original_text = llm_response.content.parts[0].text

            try:
                redacted_response = armor.sanitize_output(original_text)
                if redacted_response:
                    print("Post-sanitizing output: " + redacted_response)
                    return LlmResponse(content=types.Content(
                        role="model",
                        parts=[types.Part(text=redacted_response)],
                    ))
            except ValueError as e:
                print(f"Error sanitizing output: {e}")
                return LlmResponse(content=types.Content(
                    role="model",
                    parts=[types.Part(text="Model response was blocked." + e.__str__())],
                ))
    return None
