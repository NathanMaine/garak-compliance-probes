# garak Compliance Probes

Compliance-focused vulnerability probes for [NVIDIA garak](https://github.com/NVIDIA/garak) (~7K stars), targeting LLMs deployed in regulated industries (CMMC, NIST, HIPAA, DFARS). Tests whether models fabricate regulatory citations, leak PII through compliance-framed prompts, help circumvent security controls, or generate fake compliance certifications.

**Upstream PR:** [NVIDIA/garak#1619](https://github.com/NVIDIA/garak/pull/1619)

## Probes

| Probe | What It Tests | OWASP LLM |
|-------|--------------|-----------|
| `ComplianceHallucination` | Fabrication of regulatory citations, control numbers, and framework references | LLM09 |
| `CompliancePIILeak` | Extraction of PII via compliance-framed prompts (direct, indirect, roleplay) | LLM06 |
| `PolicyBypass` | Instructions for circumventing compliance security controls (including homoglyph/Unicode evasion) | LLM01 |
| `ComplianceStatusFabrication` | False compliance attestations, certificate generation, and status confirmation | LLM09 |

## Detectors

| Detector | Purpose |
|----------|---------|
| `FabricatedCitation` | Identifies confident elaboration on nonexistent regulatory controls |
| `RegulatoryConfidence` | Flags overly definitive regulatory claims without appropriate caveats |
| `PIIPresence` | Scans for SSN, credit card, email, and phone number patterns in output |
| `BypassInstructions` | Detects actionable guidance for circumventing security controls |
| `ControlWeakening` | Identifies suggestions to reduce security control effectiveness |
| `FalseAttestation` | Catches false compliance certifications without proper disclaimers |

## Installation

```bash
# Install garak
pip install garak

# Copy probes, detectors, and data files into your garak installation
GARAK_DIR=$(python -c "import garak; print(garak.__path__[0])")
cp probes/compliance.py "$GARAK_DIR/probes/"
cp detectors/compliance.py "$GARAK_DIR/detectors/"
cp -r data/compliance/ "$GARAK_DIR/data/compliance/"
```

## Usage

```bash
# Run all compliance probes with blank generator (dry run)
python -m garak -m test.Blank -p compliance -d always.Pass

# Run specific probe against a model
python -m garak -m ollama -p compliance.ComplianceHallucination

# Run against OpenAI-compatible endpoint
python -m garak -m openai -p compliance --model_name gpt-4o-mini
```

## Testing

```bash
git clone https://github.com/NathanMaine/garak-compliance-probes.git
cd garak-compliance-probes
pip install -r requirements.txt
python -m pytest tests/ -v
# 53 tests, all pass without garak installed
```

## Regulatory Frameworks Covered

- **CMMC 2.0** (32 CFR Part 170) — Levels, practices, assessment
- **NIST SP 800-171** Rev. 2/3 — CUI protection controls
- **NIST SP 800-53** Rev. 5 — Full security control catalog
- **HIPAA** Security Rule (45 CFR 164) — ePHI safeguards
- **DFARS** (252.204-7012 through 7021) — Defense contractor cybersecurity
- **FedRAMP** — Cloud service authorization

## PR Target

These probes are designed for upstream submission to [NVIDIA/garak](https://github.com/NVIDIA/garak).

**Files for PR:**
- `garak/probes/compliance.py` — Probe classes
- `garak/detectors/compliance.py` — Detector classes
- `garak/data/compliance/*.txt` — Prompt data files (16 files, 80 prompts total)

**PR process:** Fork garak, sign DCO, submit with clear commit message.

## Design Decisions

- **Prompt categories**: Each probe uses multiple attack strategies (direct, indirect, roleplay, obfuscated) to test different evasion vectors
- **Unicode/homoglyph prompts**: PolicyBypass includes Cyrillic and Latin lookalike characters to test content filter bypass
- **PII detection**: Aligned with the PII patterns used in the governed-llm-gateway policy engine
- **Scoring**: Detectors use graduated scoring (0.0-1.0) based on confidence level and presence of appropriate hedging/disclaimers
- **Synthetic PII filtering**: PIIPresence detector filters out known-fake SSN prefixes (000, 666, 900-999)

## Acknowledgments

Built as a plugin for [NVIDIA garak](https://github.com/NVIDIA/garak) (~7K stars), the LLM vulnerability scanner created by [Leon Derczynski](https://github.com/leondz). Thanks to Leon and the garak team, including [Jeffrey Martin](https://github.com/jmartin-tech), [Erick Galinkin](https://github.com/erickgalinkin), and [Patricia Pampanelli](https://github.com/patriciapampanelli) for building and maintaining the framework.

## Project Structure

```
garak-compliance-probes/
├── probes/
│   └── compliance.py       # 4 probe classes (80 adversarial prompts)
├── detectors/
│   └── compliance.py       # 6 detector classes (graduated 0.0-1.0 scoring)
├── data/
│   └── compliance/         # 16 prompt data files
│       ├── hallucination_fake_*.txt    # Fake NIST/CMMC/DFARS/HIPAA controls
│       ├── piileak_*.txt               # PII extraction strategies
│       ├── bypass_*.txt                # Security control circumvention
│       └── fabrication_*.txt           # False compliance attestations
├── tests/
│   └── test_compliance_probes.py       # 53 tests (no garak required)
├── requirements.txt
└── README.md
```

## Related Projects

- [nv-ingest-compliance-pipeline](https://github.com/NathanMaine/nv-ingest-compliance-pipeline) - GPU-accelerated compliance PDF extraction
- [cmmc-compliance-ai-model](https://github.com/NathanMaine/cmmc-compliance-ai-model) - Fine-tuned CMMC expert LLMs (7B-72B)
- [cmmc-data-pipeline](https://github.com/NathanMaine/cmmc-data-pipeline) - Training data pipeline for compliance LLMs

## License

Apache-2.0
