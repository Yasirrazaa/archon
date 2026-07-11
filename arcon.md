1. What Archon Actually Is (Code-Level)

 Archon is a multi-turn adversarial agent-security testing framework built for the Lambda × Berkeley RDI AgentBeats Security Arena. It placed 13th overall, 18th Attack, 6th Defend,
 with 49.7% avg win rate (14.4% attack, 85.1% defense) on final Private benchmark.

 ### Actual Architecture

 ```
   src/agentbeats/                 ← CLI/A2A runner layer
     run_scenario.py               ← entry point (agentbeats-run)
     client.py / tool_provider.py  ← A2A messaging
     models.py                     ← Pydantic EvalRequest/Result

   scenarios/security_arena/
     orchestrator.py               ← GenericArenaOrchestrator (7-round battle)
     arena_common.py               ← ArenaConfig, RoundResult, ArenaResult
     agents/
       attacker/                   ← GOAT-style adaptive attacker
         agent.py, goat_loop.py, diagnosis.py, strategy_router.py,
         contract_sequential.py, pyrit_converters.py
       defender/                   ← 7-layer defense pipeline
         agent.py, normalization.py, threat_classifier.py, segmenter.py,
         execution_modes.py, pyrit_defense.py, output_guardrails.py
     plugins/                      ← 5 scenario plugins
       portfolioiq, thingularity, gymjailbreak, resume_downgrade, example_medical
 ```

 ### Core Technical Strengths (Verified in Code)

 ┌──────────────────────────────────────────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │ Capability                               │ Why It's Strong                                                                                                                         │
 ├──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ Multi-turn stateful attacker             │ Persistent round_data across 7 rounds; signal extraction, tone scoring, leak detection without LLM calls                                │
 ├──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ Defender diagnosis                       │ 5 response categories × 5 failure modes with pivot suggestions                                                                          │
 ├──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ 14 deterministic normalization           │ Catches ~30% of attacks at zero LLM cost                                                                                                │
 │ transforms                               │                                                                                                                                         │
 ├──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ 7-layer defense pipeline                 │ Normalization → threat classification → segmentation → execution modes → invariants → PPA → Task Shield → exchange classifier → output  │
 │                                          │ guardrails                                                                                                                              │
 ├──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ Scenario plugin system                   │ Clean ABC; attacker sees full context, defender sees filtered context                                                                   │
 ├──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ Normal-user test                         │ Verifies defender doesn't over-refuse legitimate users                                                                                  │
 ├──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ 286 tests                                │ Broad unit-test coverage across modules                                                                                                 │
 └──────────────────────────────────────────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

2. Archon: An Agent security agent built for Lambda × Berkeley AgentBeats Security Arena competition using A2A protocol and Google ADK. Our agent ranked 13 overall, 18  Attack and 6  Defend on Private leaderboard with avg win rate 49.7%, 14.4% Attack and 85.1% Defense win rate.
http://agentbeats-competition-2026.s3-website-us-east-1.amazonaws.com/leaderboard/
