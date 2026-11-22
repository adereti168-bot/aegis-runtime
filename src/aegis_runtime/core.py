import copy
import hashlib
import inspect
import json
import time
from functools import wraps

GENESIS_HASH = "0" * 64


class SecurityViolation(Exception):
    pass


class AegisRuntime:
    def __init__(self, max_calls=5, state_store=None, policy=None):
        self.max_calls = max_calls
        self.call_counts = {}
        self.session_state = {}
        self.audit_log = []
        self.state_store = state_store if state_store is not None else {}
        self.snapshots = []
        self.tools = {}
        self.policy = policy or {}

        if "max_calls" in self.policy:
            self.max_calls = self.policy["max_calls"]

    @classmethod
    def from_policy(cls, policy_path, state_store=None):
        """Load deterministic Policy-as-Code rules from a JSON file."""
        with open(policy_path, "r", encoding="utf-8") as f:
            policy_data = json.load(f)
        return cls(
            max_calls=policy_data.get("max_calls", 5),
            state_store=state_store,
            policy=policy_data,
        )

    def _log_event(self, tool_name, status, args):
        prev_hash = self.audit_log[-1]["hash"] if self.audit_log else GENESIS_HASH
        payload = {
            "index": len(self.audit_log),
            "timestamp": time.time(),
            "tool": tool_name,
            "status": status,
            "args": str(args),
            "prev_hash": prev_hash,
        }
        canonical = json.dumps(payload, sort_keys=True)
        entry_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        payload["hash"] = entry_hash
        self.audit_log.append(payload)

    def export_audit_log(self, filepath="aegis_audit.json"):
        """Export the SHA-256 hash-chained audit trail to a JSON file."""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.audit_log, f, indent=2)
        return filepath

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

    def guard(self, _func=None, *, requires_state=None, sets_state=None, max_args=None):
        def decorator(func):
            sig = inspect.signature(func)

            @wraps(func)
            def wrapper(*args, **kwargs):
                tool_name = func.__name__
                tool_policy = self.policy.get("rules", {}).get(tool_name, {})

                eff_requires = {**(requires_state or {}), **tool_policy.get("requires_state", {})}
                eff_sets = {**(sets_state or {}), **tool_policy.get("sets_state", {})}
                eff_max_args = {**(max_args or {}), **tool_policy.get("max_args", {})}

                # 1. Circuit Breaker
                self.call_counts[tool_name] = self.call_counts.get(tool_name, 0) + 1
                if self.call_counts[tool_name] > self.max_calls:
                    self._log_event(tool_name, "BLOCKED_LOOP", args)
                    raise SecurityViolation(f"Circuit breaker tripped: {tool_name} exceeded {self.max_calls} calls.")

                # 2. Deterministic State Lock
                if eff_requires:
                    for key, expected_val in eff_requires.items():
                        if self.session_state.get(key) != expected_val:
                            self._log_event(tool_name, "BLOCKED_POLICY", args)
                            raise SecurityViolation(f"Policy violation: {tool_name} requires {key}={expected_val}")

                # 3. Deterministic Numeric Parameter Ceiling (Policy-as-Code)
                if eff_max_args:
                    bound = sig.bind_partial(*args, **kwargs)
                    bound.apply_defaults()
                    for arg_name, ceiling in eff_max_args.items():
                        if arg_name in bound.arguments:
                            val = bound.arguments[arg_name]
                            if isinstance(val, (int, float)) and val > ceiling:
                                self._log_event(tool_name, "BLOCKED_THRESHOLD", bound.arguments)
                                raise SecurityViolation(
                                    f"Policy violation: {tool_name} argument '{arg_name}'={val} exceeds max allowed {ceiling}"
                                )

                result = func(*args, **kwargs)
                self._log_event(tool_name, "EXECUTED", args)
                if eff_sets:
                    self.session_state.update(eff_sets)
                return result

            self.tools[func.__name__] = wrapper
            return wrapper

        if _func is not None:
            return decorator(_func)
        return decorator
