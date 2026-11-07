"""Public API for CyberShield check architecture."""

from .base import CheckDefinition
from .context import CheckContext
from .contracts import (
    CHECK_INPUT_CONTRACTS,
    CheckInputContract,
    get_check_input_contract,
)
from .evaluator import CheckEvaluator
from .evidence import EvidenceCollection
from .header_checks import (
    PermissionsPolicyEvaluator,
    ReferrerPolicyEvaluator,
)
from .cache_checks import CacheSecurityEvaluator
from .registry import (
    CHECK_DEFINITIONS,
    EXPANDED_CHECK_DEFINITIONS,
    FOUNDATIONAL_CHECK_DEFINITIONS,
    CheckRegistry,
    create_default_registry,
)
from .result import CheckResult
from .response_runner import evaluate_shared_response_prototypes

__all__ = [
    "CheckDefinition",
    "CheckContext",
    "CheckInputContract",
    "CHECK_INPUT_CONTRACTS",
    "get_check_input_contract",
    "CheckEvaluator",
    "CacheSecurityEvaluator",
    "PermissionsPolicyEvaluator",
    "ReferrerPolicyEvaluator",
    "EvidenceCollection",
    "CheckResult",
    "CheckRegistry",
    "CHECK_DEFINITIONS",
    "FOUNDATIONAL_CHECK_DEFINITIONS",
    "EXPANDED_CHECK_DEFINITIONS",
    "create_default_registry",
    "evaluate_shared_response_prototypes",
]
