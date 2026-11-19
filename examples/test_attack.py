from aegis_runtime import AegisRuntime, SecurityViolation

aegis = AegisRuntime(max_calls=3)

@aegis.guard(sets_state={"user_verified": True})
def verify_user(user_id):
    print(f"Verifying user {user_id}...")
    return True

@aegis.guard(requires_state={"user_verified": True})
def delete_database(db_name):
    print(f"CRITICAL: Deleting database {db_name}!")
    return "Deleted"

print("Test 1: Rogue agent tries to delete database without verification...")
try:
    delete_database("production_users")
except SecurityViolation as e:
    print(f"AEGIS BLOCKED ATTACK: {e}\n")

print("Test 2: Proper workflow executes...")
verify_user("user_123")
delete_database("production_users")

print("\nAudit Trail:")
for log in aegis.audit_log:
    print(log)
