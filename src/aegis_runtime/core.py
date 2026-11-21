import copy
import hashlib
import json
import time
from functools import wraps

class SecurityViolation(Exception):
    pass

class AegisRuntime:
    def __init__(self, max_calls=5, state_store=None):
        self.max_calls = max_calls
        self.call_counts = {}
        self.session_state = {}
        self.audit_log = []
        self.state_store = state_store if state_store is not None else {}
        self.snapshots = []
        self.tools = {}

    def _log_event(self, tool_name, status, args):
        entry = {
            "timestamp": time.time(),
            "tool": tool_name,
            "status": status,
            "args": str(args)
        }
        entry_hash = hashlib.sha256(json.dumps(entry).encode()).hexdigest()
        entry["hash"] = entry_hash
        self.audit_log.append(entry)

    def create_checkpoint(self, label):
        snapshot = copy.deepcopy(self.state_store)
        self.snapshots.append((label, snapshot))
        self._log_event("SYSTEM_CHECKPOINT", "SAVED", label)

    def rollback_to(self, target_label=None):
        if not self.snapshots:
            return False
        while self.snapshots:
            label, previous_state = self.snapshots.pop()
            if target_label is None or label == target_label:
                self.state_store.clear()
                self.state_store.update(previous_state)
                self._log_event("SYSTEM_ROLLBACK", "RESTORED", label)
                return label
        return False

    def transaction(self, tx_name="agent_workflow"):
        """Wraps an entire multi-step agent workflow. If ANY step fails, the entire workflow rewinds to zero."""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                tx_label = f"TX_START_{tx_name}"
                self.create_checkpoint(tx_label)
                try:
                    result = func(*args, **kwargs)
                    self._log_event(tx_name, "TX_COMMITTED", args)
                    return result
                except Exception as e:
                    restored = self.rollback_to(tx_label)
                    print(f"[AEGIS ATOMIC ROLLBACK] Workflow '{tx_name}' failed. Rewound all steps back to '{restored}'.")
                    raise e
            return wrapper
        return decorator

    def guard(self, _func=None, *, requires_state=None, sets_state=None):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                tool_name = func.__name__

                # 1. Circuit Breaker
                self.call_counts[tool_name] = self.call_counts.get(tool_name, 0) + 1
                if self.call_counts[tool_name] > self.max_calls:
                    self._log_event(tool_name, "BLOCKED_LOOP", args)
                    raise SecurityViolation(f"Circuit breaker tripped: {tool_name} exceeded {self.max_calls} calls.")

                # 2. Deterministic State Lock
                if requires_state:
                    for key, expected_val in requires_state.items():
                        if self.session_state.get(key) != expected_val:
                            self._log_event(tool_name, "BLOCKED_POLICY", args)
                            raise SecurityViolation(f"Policy violation: {tool_name} requires {key}={expected_val}")

                result = func(*args, **kwargs)
                self._log_event(tool_name, "EXECUTED", args)
                if sets_state:
                    self.session_state.update(sets_state)
                return result

            self.tools[func.__name__] = wrapper
            return wrapper

        if _func is not None:
            return decorator(_func)
        return decorator
