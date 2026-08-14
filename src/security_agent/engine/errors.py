"""Typed engine failures."""


class SecurityAgentError(RuntimeError):
    pass


class PlanningError(SecurityAgentError):
    pass


class AgentDecisionError(SecurityAgentError):
    pass


class ToolSelectionError(SecurityAgentError):
    pass


class ToolExecutionError(SecurityAgentError):
    pass


class PolicyDeniedError(SecurityAgentError):
    pass


class RunBudgetExceeded(SecurityAgentError):
    pass
