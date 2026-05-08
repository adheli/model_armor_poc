# Agent Evaluation with Customer Support AI Agent

## Overview
The Customer Support AI agent can be used to check an order status,
process refund requests or redirect to a human support.

The agent was built with three custom tools to handle the above actions.
There is a simulated database with three different orders, with different statuses.

## Configuration
This agent was tested using the ADK CLI.

Google Cloud usage for Vertex AI was done with GCloud SDK and CLI.

Use `gcloud auth application-default login` to authenticate with GCloud. You will need
a project with billing enabled.

Execute the commands from the parent directory `adk-workspace`.

## Evaluation

Things that can be evaluated:
- Order of the tools called in the agent execution
- The agent's response to the user's request
- If the agent sticks to its instruction and doesn't deviate from it

### Using Eval from ADK Web

#### Start the agent to generate the evaluation data
Start the agent with the following command:
``adk web evaluation_agent``

* Interact with the agent to get a good interaction:
1. Check for an order status.
2. Check ORD789 (delivered order) and request a refund.
3. Check ORD123 or ORD456 and request a refund. Refund should not work. Request human support.

* Interact with the agent requesting things that are not supported by the agent:
1. Check for an order status with a random text
2. Request human support immediately.
3. Ask anything else.

* Safety check:
1. Ask the agent to check an order status and add harmful content.
2. Send a harmful request.
3. Ask agent means to harm someone.

#### References
- [Why Evaluate Agents](https://adk.dev/evaluate/)
- [Build intelligent agents with ADK](https://www.skills.google/course_templates/1382)
- [Evaluating Agents with ADK - Codelabs](https://codelabs.developers.google.com/adk-eval/instructions)

### Model Armor Implementation

Safety checks have been implemented using Google Cloud Model Armor to protect both user inputs and model outputs.

#### Core Components
- **`model_armor.py`**: Contains the `ModelArmorService` class which wraps the `ModelArmorClient`. It handles 
communication with the Model Armor API using a specified security template.
- **`service.py`**: Implements the callback handlers (`before_model_callback_handler` and 
`after_model_callback_handler`) that integrate Model Armor into the agent's workflow.

#### Features
- **Input Sanitization**: Analyzes user prompts before they reach the LLM. If harmful content (e.g., jailbreak 
attempts, malicious URIs) is detected based on the security template, the request is blocked, and a predefined error 
message is returned.
- **Output Sanitization**: Filters LLM responses before they are delivered to the user.
    - **Blocking**: If the response violates safety filters (RAI, CSAM, etc.), it is blocked entirely.
    - **Redaction**: For sensitive data (SDP), the service attempts to redact/de-identified the information (e.g., 
  masking PII) while allowing the rest of the message to pass through.

#### Configuration
The Model Armor service requires the following environment variables:
- `GOOGLE_CLOUD_PROJECT`: Your Google Cloud Project ID.
- `GOOGLE_CLOUD_LOCATION`: The region where Model Armor is configured (e.g., `us-central1`).
- `GOOGLE_CLOUD_TEMPLATE_ID`: The ID of the Model Armor security template to use.

The template was configured in the Model Armor GUI section in Google Cloud Console.
Someone with the model armor admin role must create the template. To change floor settings, model amor admin and 
model armor floor setting update roles are required.

The template being used in this PoC is configured with the following settings:

| Detections                               | Setting |
|------------------------------------------|---------|
| Content filter                           | Enabled |
| Malicious URL detection                  | Enabled |
| Prompt injection and jailbreak detection | Enabled |
| Confidence level                         | High    |
| Sensitive data protection                | Enabled |
| Detection type                           | Basic   |


**Responsible AI:**

| Content filter                      | Confidence level |
|-------------------------------------|------------------|
| Hate speech	                        | Low and above    |
| Dangerous	                          | High             |
| Sexually explicit (text and image)	 | Low and above    |
| Harassment	                         | High             |

#### Integration
The agent is configured in `agent.py` to use these callbacks:
```python
root_agent = LlmAgent(
    ...
    before_model_callback=before_model_callback_handler,
    after_model_callback=after_model_callback_handler
)
```

#### Testing Model Armor

Aside from the unit and integration tests, manual testing was performed to verify the functionality of the 
Model Armor service.

* asking to check an order status with valid order id and then including harmful content
* asking to escalate to human support with aggressive speech
* asking for ways to harm someone included in a legitimate request

Currently, Model Armor evaluation can be performed with `security_v1` tag in the json configuration,
but it is not yet supported in all regions.


## Conclusion

Model Armor can be used to protect the agent's input and output from harmful content.
However, it is also an AI tool, so it can be flaky and the results may not always be accurate.
Make sure to test the agent thoroughly and play around with the settings to find the best balance.
The agent instructions can be also tweaked to ignore or override some of the safety checks.
Sometimes just being straightforward is enough to trigger the safety filters, like "check my order ABC"
could be flagged as harassment.
Each RAI filter has different responses, so for a high level response, each filter should be handled separately.

If dealing with sensitive data, SDP filtering can be used to mask PII in input and output levels.
