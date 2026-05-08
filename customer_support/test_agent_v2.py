import os

import pytest
from dotenv import load_dotenv
from google.adk.evaluation.agent_evaluator import AgentEvaluator

load_dotenv()


@pytest.mark.asyncio
async def test_customer_support_agent():
    """Tests the customer support agent using an evaluation set.

    This test loads the evaluation dataset and runs the agent against it using
    the AgentEvaluator.
    """
    # Path to the evaluation set
    file_name="eval_set_v2.evalset.json"
    eval_set_path = os.path.dirname(__file__) + "/" + file_name
    
    # Run evaluation
    # agent_module should be the import path to the agent file
    # since we are in evaluation_agent/customer_support, and agent.py is here
    # we can use 'evaluation_agent.customer_support.agent'
    # agent_name is 'root_agent' as defined in agent.py
    
    await AgentEvaluator.evaluate(
        agent_module="customer_support.agent",
        eval_dataset_file_path_or_dir=eval_set_path,
        num_runs=1
    )
