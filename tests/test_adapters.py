from aegis_runtime import AegisRuntime, AegisAgentAdapter


def test_adapter_schemas_and_execution():
    aegis = AegisRuntime()

    @aegis.guard(sets_state={"verified": True})
    def verify_user(user_id: str) -> str:
        """Verifies a user's identity."""
        return f"Verified {user_id}"

    @aegis.guard(requires_state={"verified": True})
    def transfer_funds(recipient: str, amount: float) -> str:
        """Transfers funds to a recipient."""
        return f"Transferred ${amount} to {recipient}"

    adapter = AegisAgentAdapter(aegis)

    # 1. Verify OpenAI / Groq / LangGraph schema export
    openai_tools = adapter.to_openai_tools()
    assert len(openai_tools) == 2
    assert openai_tools[0]["function"]["name"] == "verify_user"

    # 2. Verify Anthropic schema export
    anthropic_tools = adapter.to_anthropic_tools()
    assert len(anthropic_tools) == 2
    assert anthropic_tools[1]["name"] == "transfer_funds"

    # 3. Verify unverified tool call is blocked by state lock
    blocked = adapter.execute_tool_call(
        "transfer_funds", '{"recipient": "Alice", "amount": 500.0}'
    )
    assert blocked["status"] == "blocked"

    # 4. Verify state unlock and allowed execution
    verified = adapter.execute_tool_call("verify_user", {"user_id": "u_123"})
    assert verified["status"] == "success"

    allowed = adapter.execute_tool_call(
        "transfer_funds", '{"recipient": "Alice", "amount": 500.0}'
    )
    assert allowed["status"] == "success"
    assert allowed["result"] == "Transferred $500.0 to Alice"

    # 5. Verify unknown tool is blocked
    unknown = adapter.execute_tool_call("drop_database", "{}")
    assert unknown["status"] == "blocked"

    print("ALL v0.3.0 ADAPTER TESTS PASSED!")


if __name__ == "__main__":
    test_adapter_schemas_and_execution()
