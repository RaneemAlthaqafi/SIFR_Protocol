from examples.demo_two_agents import run_demo
from examples.demo_unauthorized_action import run_demo as run_unauthorized


def test_end_to_end_calculator_flow_returns_5():
    assert run_demo() == 5


def test_unauthorized_flow_rejects():
    assert run_unauthorized() == "UNAUTHORIZED_ACTION"
