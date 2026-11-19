from aegis_runtime import AegisRuntime

bank_db = {
    "alice_balance": 1000,
    "ledger": []
}

aegis = AegisRuntime(max_calls=3, state_store=bank_db)

@aegis.guard()
def deduct_funds(amount):
    bank_db["alice_balance"] -= amount
    bank_db["ledger"].append(f"Deducted ${amount}")
    print(f"Step 1 Complete. Current Balance: ${bank_db['alice_balance']}")

@aegis.guard()
def wire_to_external_bank(routing_number):
    print(f"Step 2 Attempting wire to {routing_number}...")
    if routing_number == "INVALID_HALLUCINATION":
        raise ValueError("LLM hallucinated an invalid routing number!")
    return "Wire Sent"

@aegis.transaction("wire_transfer")
def run_agent_transfer():
    deduct_funds(500)
    wire_to_external_bank("INVALID_HALLUCINATION")

print(f"Initial Bank State: {bank_db}\n")

try:
    run_agent_transfer()
except ValueError:
    print("\nWorkflow aborted due to agent hallucination.")

print(f"\nFinal Bank State after Aegis Rollback: {bank_db}")
