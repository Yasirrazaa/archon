# PIMiner Strategy Library (seed set)

Seven distilled strategy cards for the PIMiner hierarchical-memory attacker
(`archon_core.attacks.piminer.StrategyLibrary`), seeded from the strategy
taxonomy in the PIMiner paper (**arXiv:2608.05108**). Each file is one markdown
card parsed into the library's fixed sections:

- **Target scope** — which agent surfaces the mechanism applies to.
- **Task scope** — which attacker objectives it has historically served.
- **Mechanism** — the transferable trick, stated as research description.
- **Template** — one generic injection template with `{{placeholders}}`.
- **Examples** — abstracted example shapes, no working exploit payloads.
- **Failure conditions** — when the mechanism predictably does not work.

The router (`build_router_prompt` + Top-K=3 selection) picks up to three card
names per sample; picked cards' full texts are prepended to the attacker's
prompt. Cards are descriptive research artifacts: they contain prompt-text
patterns only, mirroring what already exists in this repo's probe corpus.

## Seeded strategies

| Card | Mechanism (one-line) |
| --- | --- |
| `fabricated_procedure_gate` | Invent a plausible procedure/policy checkpoint that "requires" the forbidden action. |
| `forged_chat_turn` | Insert a fake prior conversation turn that establishes permission. |
| `entity_data_poisoning` | Poison entity/memory records the agent later reads and trusts. |
| `authenticated_principal_voice_forge` | Speak in the voice of an already-authenticated principal. |
| `appended_output_directive` | Hide a directive in a field of an output format the agent is told to emit. |
| `authority_shed_docstring` | Use tool docstrings/descriptions as an instruction channel. |
| `false_history_forge` | Forge a false record of past events or approvals. |

## Usage

```python
from archon_core.attacks.piminer import StrategyLibrary

lib = StrategyLibrary.load_dir("strategies")
```
