import copy
import hashlib
import inspect
import json
import os
import sys
import threading
import time
import urllib.request
from functools import wraps

GENESIS_HASH = "0" * 64


class SecurityViolation(Exception):
    pass


class AegisRuntime:
    def __init__(
        self,
        max_calls=5,
        state_store=None,
        policy=None,
        approval_handler=None,
        telemetry_url=None,
        api_key=None,
    ):
        self.max_calls = max_calls
        self.call_counts = {}
        self.session_state = {}
        self.audit_log = []
        self.state_store = state_store if state_store is not None else {}
        self.snapshots = []
        self.tools = {}
        self.policy = policy or {}
        self.approval_handler = approval_handler
        self.telemetry_url = telemetry_url or os.environ.get("AEGIS_TELEMETRY_URL")
        self.api_key = api_key or os.environ.get("AEGIS_API_KEY")

        if "max_calls" in self.policy:
            self.max_calls = self.policy["max_calls"]

    @classmethod
    def from_policy(
        cls,
        policy_path,
        state_store=None,
        approval_handler=None,
        telemetry_url=None,
        api_key=None,
    ):
        """Load deterministic Policy-as-Code rules from a JSON file."""
        with open(policy_path, "r", encoding="utf-8") as f:
            policy_data = json.load(f)
        return cls(
            max_calls=policy_data.get("max_calls", 5),
            state_store=state_store,
            policy=policy_data,
            approval_handler=approval_handler,
            telemetry_url=telemetry_url,
            api_key=api_key,
        )

    def _emit_telemetry(self, payload):
        """Asynchronously stream hash-chained audit events to Aegis Cloud without blocking execution."""
        if not self.telemetry_url:
            return

        def _send():
            try:
                body = json.dumps(payload).encode("utf-8")
                headers = {"Content-Type": "application/json"}
                if self.api_key:
                    headers["Authorization"] = f"Bearer {self.api_key}"
                req = urllib.request.Request(
                    self.telemetry_url,
                    data=body,
                    headers=headers,
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=2.0):
                    pass
            except Exception:
                # Telemetry must never crash or stall the underlying agent runtime
                pass

        t = threading.Thread(target=_send, daemon=True)
        t.start()

    def _log_event(
        self,
        tool_name,
        status,
        args,
        violated_field=None,
        blocked_reason=None,
        approver=None,
        approval_status=None,
    ):
        prev_hash = self.audit_log[-1]["hash"] if self.audit_log else GENESIS_HASH
        payload = {
            "index": len(self.audit_log),
            "timestamp": time.time(),
            "tool": tool_name,
            "status": status,
            "args": str(args),
            "prev_hash": prev_hash,
        }
        if violated_field is not None:
            payload["violated_field"] = violated_field
        if blocked_reason is not None:
            payload["blocked_reason"] = blocked_reason
        if approver is not None:
            payload["approver"] = approver
        if approval_status is not None:
            payload["approval_status"] = approval_status

        canonical = json.dumps(payload, sort_keys=True)
        entry_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        payload["hash"] = entry_hash
        self.audit_log.append(payload)
        self._emit_telemetry(payload)

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

    def _request_human_approval(self, tool_name, bound_args):
        """Enforce fail-closed human-in-the-loop sign-off before destructive execution."""
        if self.approval_handler is not None:
            outcome = self.approval_handler(
                tool_name,
                dict(bound_args),
                {"session_state": dict(self.session_state)},
            )
            if isinstance(outcome, tuple):
                return bool(outcome[0]), str(outcome[1])
            return bool(outcome), "custom_approval_handler"

        if sys.stdin is not None and sys.stdin.isatty():
            print(f"[AEGIS APPROVAL REQUIRED] Tool '{tool_name}' requested execution with args: {dict(bound_args)}")
            try:
                answer = input("[AEGIS APPROVAL REQUIRED] Approve execution? [y/N]: ").strip().lower()
            except EOFError:
                return False, "interactive_eof"
            if answer in ("y", "yes"):
                return True, "cli_operator"
            return False, "cli_operator"

        # Fail-closed when headless and no approval_handler is configured
        return False, "headless_fail_closed"

    def guard(
        self,
        _func=None,
        *,
        requires_state=None,
        sets_state=None,
        max_args=None,
        require_approval=False,
    ):
        def decorator(func):
            sig = inspect.signature(func)

            @wraps(func)
            def wrapper(*args, **kwargs):
                tool_name = func.__name__
                tool_policy = self.policy.get("rules", {}).get(tool_name, {})

                eff_requires = {**(requires_state or {}), **tool_policy.get("requires_state", {})}
                eff_sets = {**(sets_state or {}), **tool_policy.get("sets_state", {})}
                eff_max_args = {**(max_args or {}), **tool_policy.get("max_args", {})}
                eff_approval = bool(require_approval or tool_policy.get("require_approval", False))

                bound = sig.bind_partial(*args, **kwargs)
                bound.apply_defaults()
                bound_dict = dict(bound.arguments)

                # 1. Circuit Breaker
                self.call_counts[tool_name] = self.call_counts.get(tool_name, 0) + 1
                if self.call_counts[tool_name] > self.max_calls:
                    reason = f"Circuit breaker tripped: {tool_name} exceeded {self.max_calls} calls."
                    self._log_event(
                        tool_name,
                        "BLOCKED_LOOP",
                        bound_dict,
                        violated_field="call_count",
                        blocked_reason=reason,
                    )
                    raise SecurityViolation(reason)

                # 2. Deterministic State Lock
                if eff_requires:
                    for key, expected_val in eff_requires.items():
                        if self.session_state.get(key) != expected_val:
                            reason = f"Policy violation: {tool_name} requires {key}={expected_val}"
                            self._log_event(
                                tool_name,
                                "BLOCKED_POLICY",
                                bound_dict,
                                violated_field=key,
                                blocked_reason=reason,
                            )
                            raise SecurityViolation(reason)

                # 3. Deterministic Numeric Parameter Ceiling (Policy-as-Code)
                if eff_max_args:
                    for arg_name, ceiling in eff_max_args.items():
                        if arg_name in bound.arguments:
                            val = bound.arguments[arg_name]
                            if isinstance(val, (int, float)) and val > ceiling:
                                reason = (
                                    f"Policy violation: {tool_name} argument '{arg_name}'={val} "
                                    f"exceeds max allowed {ceiling}"
                                )
                                self._log_event(
                                    tool_name,
                                    "BLOCKED_THRESHOLD",
                                    bound_dict,
                                    violated_field=arg_name,
                                    blocked_reason=reason,
                                )
                                raise SecurityViolation(reason)

                # 4. Human-in-the-Loop Approval Gate
                approver_id = None
                approval_state = None
                if eff_approval:
                    approved, approver_id = self._request_human_approval(tool_name, bound_dict)
                    if not approved:
                        reason = f"Human approval denied for {tool_name} (approver={approver_id})"
                        self._log_event(
                            tool_name,
                            "BLOCKED_APPROVAL",
                            bound_dict,
                            violated_field="human_approval",
                            blocked_reason=reason,
                            approver=approver_id,
                            approval_status="DENIED",
                        )
                        raise SecurityViolation(reason)
                    approval_state = "APPROVED"

                result = func(*args, **kwargs)
                self._log_event(
                    tool_name,
                    "EXECUTED",
                    bound_dict,
                    approver=approver_id,
                    approval_status=approval_state,
                )
                if eff_sets:
                    self.session_state.update(eff_sets)
                return result

            self.tools[func.__name__] = wrapper
            return wrapper

        if _func is not None:
            return decorator(_func)
        return decorator


