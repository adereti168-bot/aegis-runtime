import inspect
import json
from typing import Any, Callable, Dict, List, get_type_hints


class AegisAgentAdapter:
    """
    Universal zero-dependency adapter bridging AegisRuntime-guarded tools
    with OpenAI, Groq, Anthropic, LangGraph, and n8n webhook payloads.
    """

    def __init__(self, runtime: Any):
        self.runtime = runtime

    def _python_type_to_json_type(self, py_type: Any) -> str:
        mapping = {
            int: "integer",
            float: "number",
            str: "string",
            bool: "boolean",
            list: "array",
            dict: "object",
        }
        return mapping.get(py_type, "string")

    def _extract_schema(self, func: Callable) -> Dict[str, Any]:
        sig = inspect.signature(func)
        type_hints = get_type_hints(func)
        properties: Dict[str, Any] = {}
        required: List[str] = []

        for param_name, param in sig.parameters.items():
            if param_name in ("self", "cls"):
                continue
            annotated_type = type_hints.get(param_name, str)
            json_type = self._python_type_to_json_type(annotated_type)
            properties[param_name] = {
                "type": json_type,
                "description": f"Parameter '{param_name}' ({json_type})",
            }
            if param.default is inspect.Parameter.empty:
                required.append(param_name)

        return {
            "type": "object",
            "properties": properties,
            "required": required,
        }

    def to_openai_tools(self) -> List[Dict[str, Any]]:
        """Exports guarded tools in OpenAI / Groq / LangGraph tool-calling format."""
        tools_schema = []
        for name, func in self.runtime.tools.items():
            doc = inspect.getdoc(func) or f"Guarded Aegis tool: {name}"
            tools_schema.append(
                {
                    "type": "function",
                    "function": {
                        "name": name,
                        "description": doc,
                        "parameters": self._extract_schema(func),
                    },
                }
            )
        return tools_schema

    def to_anthropic_tools(self) -> List[Dict[str, Any]]:
        """Exports guarded tools in Anthropic Claude tool-use format."""
        tools_schema = []
        for name, func in self.runtime.tools.items():
            doc = inspect.getdoc(func) or f"Guarded Aegis tool: {name}"
            tools_schema.append(
                {
                    "name": name,
                    "description": doc,
                    "input_schema": self._extract_schema(func),
                }
            )
        return tools_schema

    def execute_tool_call(self, tool_name: str, arguments: Any) -> Dict[str, Any]:
        """
        Safely executes a tool call from an LLM response or n8n webhook payload
        through the AegisRuntime guardrails.
        """
        if tool_name not in self.runtime.tools:
            return {
                "status": "blocked",
                "tool": tool_name,
                "error": f"Unauthorized or unregistered tool: '{tool_name}'",
            }

        if isinstance(arguments, str):
            try:
                parsed_args = json.loads(arguments) if arguments.strip() else {}
            except json.JSONDecodeError as exc:
                return {
                    "status": "error",
                    "tool": tool_name,
                    "error": f"Invalid JSON arguments: {exc}",
                }
        elif isinstance(arguments, dict):
            parsed_args = arguments
        else:
            return {
                "status": "error",
                "tool": tool_name,
                "error": "Arguments must be a JSON string or dictionary.",
            }

        func = self.runtime.tools[tool_name]
        try:
            result = func(**parsed_args)
            return {
                "status": "success",
                "tool": tool_name,
                "result": result,
            }
        except Exception as exc:
            return {
                "status": "blocked",
                "tool": tool_name,
                "error": str(exc),
            }
