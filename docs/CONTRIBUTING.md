# Contributing to WhiteHatHacker AI

Thank you for your interest in contributing! This guide covers the development workflow, coding standards, and submission process.

---

## Development Setup

```bash
# Clone
git clone https://github.com/your-org/whitehathackerai-bot-2.git
cd whitehathackerai-bot-2

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Verify
make health
make test
```

---

## Coding Standards

### Python Style

- **Python 3.11+** features required (type hints, match-case, async/await)
- **Line length:** 120 characters max
- **Formatter:** Black + Ruff
- **Type checker:** mypy (strict mode)

### Module Requirements

Every module MUST have:
1. Module-level docstring
2. Type annotations on all functions and methods
3. Proper error handling (no bare `except:`)
4. Structured logging via `loguru`

### Example

```python
"""Module description — one line summary.

Extended description if needed.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

from loguru import logger
from pydantic import BaseModel

from src.tools.base import SecurityTool, ToolResult


class MyResult(BaseModel):
    """Result model with full type annotations."""

    name: str
    score: float
    details: Optional[str] = None


async def do_something(target: str, timeout: int = 30) -> MyResult:
    """One-line summary of function.

    Args:
        target: The target to process.
        timeout: Timeout in seconds.

    Returns:
        MyResult with processed data.

    Raises:
        ValueError: If target is empty.
    """
    if not target:
        raise ValueError("Target cannot be empty")

    logger.info("Processing target: {}", target)
    # Implementation...
    return MyResult(name=target, score=1.0)
```

### Import Order

```python
# 1. Standard library
import asyncio
import json
from pathlib import Path

# 2. Third-party
from pydantic import BaseModel
from loguru import logger

# 3. Local
from src.brain.engine import BrainEngine
from src.tools.base import SecurityTool
```

---

## Adding a New Tool Wrapper

1. Create the wrapper file in the appropriate category:
   ```
   src/tools/{category}/{tool_name}_wrapper.py
   ```

2. Implement the `SecurityTool` interface:
   ```python
   from src.tools.base import SecurityTool, ToolResult, Finding

   class MyToolWrapper(SecurityTool):
       name = "mytool"
       category = ToolCategory.SCANNER
       binary_name = "mytool"

       async def run(self, target: str, options: dict | None = None) -> ToolResult:
           ...

       def parse_output(self, raw_output: str) -> list[Finding]:
           ...

       def is_available(self) -> bool:
           ...
   ```

3. Register in the category `__init__.py`:
   ```python
   from .mytool_wrapper import MyToolWrapper
   ```

4. Add tests in `tests/test_tools/`

5. Add entry to `docs/TOOL_CATALOG.md`

---

## Adding a New FP Pattern

1. Add the pattern to `src/fp_engine/patterns/known_fps.py`
2. Add test case in `tests/test_fp_engine/`
3. Document the pattern (tool, condition, why it's a false positive)

---

## Testing

```bash
# Run all tests
make test

# Run with coverage
make test-cov

# Run specific suite
make test-brain
make test-tools
make test-fp

# Run only fast tests
make test-fast
```

### Test Requirements

- Every new function needs at least one unit test
- Use `pytest` fixtures from `tests/conftest.py`
- Mock external tool calls (never run real tools in tests)
- Use `pytest.mark.integration` for tests requiring actual tools
- Use `pytest.mark.slow` for long-running tests

---

## Commit Messages

Follow Conventional Commits:

```
feat(brain): add dual-model routing logic
fix(fp-engine): correct WAF detection false positive
refactor(tools): unified tool output parser
docs(workflow): update pipeline documentation
test(scanner): add nuclei wrapper unit tests
chore(deps): update pydantic to 2.10
```

**Types:** `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `ci`

**Scopes:** `brain`, `tools`, `workflow`, `fp-engine`, `reporting`, `analysis`, `cli`, `api`, `config`, `docker`, `deps`

---

## Pull Request Process

1. Create a feature branch: `git checkout -b feat/my-feature`
2. Make changes with tests
3. Ensure all checks pass:
   ```bash
   make check        # lint + typecheck
   make test         # all tests
   make compile-check # syntax validation
   ```
4. Push and open PR with description of changes
5. Address review feedback
6. Squash-merge when approved

---

## Security Considerations

When contributing, ensure:

- **Never** log API keys, tokens, or credentials
- **Always** validate targets against scope before any request
- **Always** respect rate limits
- **Never** include real vulnerability data in tests (use mock data)
- **Never** commit `.env` files or model files

---

## Architecture Decision Records

Major architectural decisions should be documented. When proposing a significant change:

1. Open an issue with the "architecture" label
2. Describe the problem, proposed solution, and alternatives
3. Get team consensus before implementing

---

## Questions?

Open an issue with the "question" label or reach out to the maintainers.
