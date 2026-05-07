import pytest
from unittest.mock import MagicMock, patch
from google.adk.agents.callback_context import CallbackContext
from google.adk.models import LlmRequest, LlmResponse
from google.genai import types
from customer_support.service import before_model_callback_handler, after_model_callback_handler

@pytest.fixture
def mock_callback_context():
    context = MagicMock(spec=CallbackContext)
    context.agent_name = "test_agent"
    return context

@pytest.fixture
def mock_llm_request():
    request = MagicMock(spec=LlmRequest)
    request.contents = [types.Content(role="user", parts=[types.Part(text="Hello")])]
    return request

@pytest.fixture
def mock_llm_response():
    response = MagicMock(spec=LlmResponse)
    response.content = types.Content(role="model", parts=[types.Part(text="Hi there")])
    return response

@patch("customer_support.service.armor")
def test_before_model_callback_handler_success(mock_armor, mock_callback_context, mock_llm_request):
    mock_armor.sanitize_input.return_value = None
    
    result = before_model_callback_handler(mock_callback_context, mock_llm_request)
    
    assert result is None
    mock_armor.sanitize_input.assert_called_once_with("Hello")

@patch("customer_support.service.armor")
def test_before_model_callback_handler_blocked(mock_armor, mock_callback_context, mock_llm_request):
    mock_armor.sanitize_input.side_effect = ValueError("Blocked")
    
    result = before_model_callback_handler(mock_callback_context, mock_llm_request)
    
    assert isinstance(result, LlmResponse)
    assert "Your request cannot be processed.Blocked" in result.content.parts[0].text

@patch("customer_support.service.armor")
def test_after_model_callback_handler_success(mock_armor, mock_callback_context, mock_llm_response):
    mock_armor.sanitize_output.return_value = None
    
    result = after_model_callback_handler(mock_callback_context, mock_llm_response)
    
    assert result is None
    mock_armor.sanitize_output.assert_called_once_with("Hi there")

@patch("customer_support.service.armor")
def test_after_model_callback_handler_redacted(mock_armor, mock_callback_context, mock_llm_response):
    mock_armor.sanitize_output.return_value = "Redacted hi"
    
    result = after_model_callback_handler(mock_callback_context, mock_llm_response)
    
    assert isinstance(result, LlmResponse)
    assert result.content.parts[0].text == "Redacted hi"

@patch("customer_support.service.armor")
def test_after_model_callback_handler_blocked(mock_armor, mock_callback_context, mock_llm_response):
    mock_armor.sanitize_output.side_effect = ValueError("Blocked")
    
    result = after_model_callback_handler(mock_callback_context, mock_llm_response)
    
    assert isinstance(result, LlmResponse)
    assert "Model response was blocked.Blocked" in result.content.parts[0].text
