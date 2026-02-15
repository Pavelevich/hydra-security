# Competitive Comparison Matrix

## AgenC Security Swarm vs Existing Solutions

Note: This matrix mixes current-state facts and target-state hypotheses.
Items marked as "Target" are goals pending benchmark validation.

### vs OpenAI Aardvark

| Feature | Aardvark | AgenC Swarm | Status |
|---------|----------|-------------|--------|
| Architecture | Publicly described as staged pipeline | Multi-agent swarm | Different design choices |
| Validation | Sandbox exploit confirmation | Adversarial Red/Blue + sandbox | Target advantage |
| Parallelism | Not fully disclosed | Parallel specialist scanners | Target advantage |
| Specialization | General-purpose | Domain-specific agents | Target advantage |
| Solana support | Not publicly positioned for Solana specialization | Native Anchor/Solana agents | Target advantage |
| Customization | Managed product model | Self-hosted/configurable | Design tradeoff |
| Transparency | Product-facing explanations | Full internal reasoning traces | Target advantage |
| Model flexibility | Not publicly disclosed in detail | Multi-model routing | Target advantage |
| Pricing | Not publicly specified | Estimated ~$3.41/scan (planning) | TBD by telemetry |
| Maturity | Private beta, backed by OpenAI | In development | Aardvark current advantage |
| Scale | OpenAI cloud platform | Self-hosted architecture | Different deployment model |
| Detection rate | 92% reported on OpenAI benchmarks | Target: >92% on defined protocol | TBD by evaluation |

### vs Traditional SAST Tools (Semgrep, CodeQL, SonarQube)

| Feature | Traditional SAST | AgenC Swarm |
|---------|-----------------|-------------|
| Method | Pattern/rule matching | LLM reasoning |
| False positives | High (30-70%) | Low (<5% target) |
| Logic bugs | Cannot detect | Can reason about |
| Custom rules | Requires rule authoring | Learns from context |
| Zero-day patterns | Only known patterns | Can identify novel patterns |
| Patching | None | Auto-generates patches |
| Solana | Very limited (Rustle only) | Deep specialization |

### vs Solana-Specific Auditors (Sec3, OtterSec, Neodyme)

| Feature | Human Auditors | AgenC Swarm |
|---------|---------------|-------------|
| Cost | $50k-200k per audit | ~$3.41 per scan |
| Speed | 2-6 weeks | Minutes |
| Coverage | Depends on auditor | Systematic, comprehensive |
| Availability | Queue/waitlist | On-demand, 24/7 |
| Consistency | Varies by auditor | Deterministic pipeline |
| Novel findings | Strongest here | Learning and improving |
| Trust/reputation | Established brands | Must be proven |
| Continuous | Point-in-time | Every commit |

### vs GitHub Copilot Security / Amazon CodeGuru

| Feature | Copilot/CodeGuru | AgenC Swarm |
|---------|-----------------|-------------|
| Detection | Pattern-based + light ML | Deep LLM reasoning |
| Validation | None (just flags) | Sandbox exploit confirmation |
| Patching | Basic suggestions | Full patches + adversarial review |
| Adversarial | No | Red vs Blue team |
| Solana | No | Deep specialization |
| Customization | Minimal | Full pipeline control |

## Proposed Differentiators (To Validate)

1. **Adversarial Validation**: No other tool pits attacker vs defender agents
2. **Solana-Native**: Deep Anchor/Solana specialization with economic attack modeling
3. **Multi-Model Routing**: Right model for each task (cost + quality optimization)
4. **Full Reasoning Traces**: Complete audit trail of how each decision was made
5. **Continuous + Deep**: Both commit-level scanning AND deep adversarial validation
6. **Self-Improving**: Track false positives/negatives to tune prompts over time

## Market Position

```
                    HIGH DEPTH
                        |
                        |
   Human Auditors  ●    |    ● AgenC Swarm
                        |
                        |
                        |    ● Aardvark
                        |
                        |
   ─────────────────────┼──────────────────
   SLOW/EXPENSIVE       |     FAST/CHEAP
                        |
                        |
         Semgrep ●      |    ● Copilot Security
                        |
      SonarQube ●       |    ● CodeGuru
                        |
                    LOW DEPTH
```

Target: Top-right quadrant -- fast, cheap, AND deep.
