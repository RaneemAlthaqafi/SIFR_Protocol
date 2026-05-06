# Related Work Notes

These notes summarize real sources used in `paper/references.bib`. They are written as working research notes rather than final prose.

## Model Context Protocol

Title: Model Context Protocol Specification  
Authors / org: MCP maintainers / Anthropic ecosystem  
Year: 2024  
Source: Official specification  
URL: https://modelcontextprotocol.io/specification/2024-11-05/  
Key claims: MCP standardizes JSON-RPC communication among hosts, clients, and servers exposing resources, prompts, and tools.  
How it supports SIFR: It validates the need for standardized model-tool/context integration.  
How it challenges SIFR: MCP already solves a significant part of tool interoperability; SIFR must be clear that it is not merely another connector format.  
Limitations: Trust and authorization decisions are largely implementation-dependent.  
BibTeX: `mcp2024spec`

Title: Introducing the Model Context Protocol  
Authors / org: Anthropic  
Year: 2024  
Source: Official announcement  
URL: https://www.anthropic.com/research/model-context-protocol  
Key claims: MCP aims to replace fragmented connectors with a standard protocol for data and tool integration.  
How it supports SIFR: Supports the broader motivation that agent/tool ecosystems need protocol standardization.  
How it challenges SIFR: Ecosystem adoption may favor extending MCP rather than introducing a separate protocol.  
Limitations: Announcement rather than normative specification.  
BibTeX: `anthropic2024mcp`

## Agent2Agent, ACP, and ANP

Title: Agent2Agent Protocol Specification  
Authors / org: A2A Protocol Working Group  
Year: 2025  
Source: Official specification  
URL: https://a2a-protocol.org/latest/specification/  
Key claims: A2A supports agent discovery, task exchange, modality negotiation, and secure communication between opaque agents.  
How it supports SIFR: Confirms that agent-to-agent interoperability is an active standardization direction.  
How it challenges SIFR: A2A overlaps with discovery and task semantics; SIFR must focus on signed frame, capability, and audit-DAG contribution.  
Limitations: Fast-moving specification; implementation maturity varies.  
BibTeX: `a2a2025spec`

Title: A2A: A New Era of Agent Interoperability  
Authors / org: Google Developers  
Year: 2025  
Source: Official blog  
URL: https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/  
Key claims: A2A was introduced as an open protocol for heterogeneous enterprise agents.  
How it supports SIFR: Shows industry interest in framework-neutral agent interoperability.  
How it challenges SIFR: SIFR must avoid pretending to replace or out-standardize a larger ecosystem.  
Limitations: Positioning document, not a peer-reviewed evaluation.  
BibTeX: `google2025a2a`

Title: Agent Communication Protocol Repository / Specification  
Authors / org: i-am-bee / IBM BeeAI  
Year: 2025  
Source: Official GitHub repository  
URL: https://github.com/i-am-bee/acp  
Key claims: ACP supports rich messages, streaming, discovery, long-running tasks, and shared state.  
How it supports SIFR: Supports the idea that agent messages need richer semantics than one-shot HTTP calls.  
How it challenges SIFR: ACP covers many communication features SIFR might otherwise claim as novel.  
Limitations: ACP is evolving and closely related to the A2A transition.  
BibTeX: `beeai2025acp`

Title: Agent Communication Protocol  
Authors / org: IBM Research  
Year: 2025  
Source: Official project page  
URL: https://research.ibm.com/projects/agent-communication-protocol  
Key claims: ACP is HTTP-native and intended for framework/language/runtime-independent agent interoperability.  
How it supports SIFR: Supports SIFR's interoperability motivation.  
How it challenges SIFR: Shows that HTTP-native agent protocols may be enough for many use cases.  
Limitations: Project page, not peer-reviewed.  
BibTeX: `ibm2025acp`

Title: Agent Network Protocol Technical White Paper  
Authors: Gaowei Chang, Eidan Lin, Chengxuan Yuan, Rizhao Cai, Binbin Chen, Xuan Xie, Yin Zhang  
Year: 2025  
Source: arXiv / ANP community white paper  
DOI: https://doi.org/10.48550/arXiv.2508.00007  
Key claims: ANP proposes identity, encrypted communication, meta-protocol negotiation, and application protocol layers for agent networks.  
How it supports SIFR: Supports the identity and negotiation motivations behind SIFR.  
How it challenges SIFR: ANP may already address parts of agent-network identity and negotiation.  
Limitations: Preprint/white paper; not a standards-body recommendation.  
BibTeX: `chang2025anp`

## Structured Agent Communication

Title: KQML as an Agent Communication Language  
Authors: Tim Finin, Yannis Labrou, James Mayfield  
Year: 1997  
Source: Software Agents, MIT Press  
URL: https://research.cs.umbc.edu/kqml/papers/  
Key claims: KQML uses performatives for knowledge/query exchange among agents.  
How it supports SIFR: Establishes historical precedent for typed agent communication acts.  
How it challenges SIFR: Demonstrates that structured agent messages are not new by themselves.  
Limitations: No modern LLM or tool-security model.  
BibTeX: `finin1997kqml`

Title: FIPA ACL Message Structure Specification  
Authors / org: Foundation for Intelligent Physical Agents  
Year: 2002  
Source: Official standard  
URL: http://www.fipa.org/specs/fipa00061/SC00061G.pdf  
Key claims: Defines envelope fields for agent communication.  
How it supports SIFR: Provides protocol lineage for message envelope design.  
How it challenges SIFR: SIFR must articulate why older ACLs are insufficient for LLM tool use.  
Limitations: Pre-LLM assumptions and symbolic semantics.  
BibTeX: `fipa2002aclmessage`

Title: FIPA Communicative Act Library Specification  
Authors / org: Foundation for Intelligent Physical Agents  
Year: 2002  
Source: Official standard  
URL: http://www.fipa.org/specs/fipa00037/SC00037J.pdf  
Key claims: Defines communicative acts such as inform, request, query, and call for proposal.  
How it supports SIFR: Supports using message type semantics rather than untyped text.  
How it challenges SIFR: Speech-act style taxonomies can be brittle when applied to probabilistic LLM outputs.  
Limitations: Not designed for signed tool calls or audit DAGs.  
BibTeX: `fipa2002communicativeacts`

Title: ReAct: Synergizing Reasoning and Acting in Language Models  
Authors: Shunyu Yao, Jeffrey Zhao, Dian Yu, Nan Du, Izhak Shafran, Karthik Narasimhan, Yuan Cao  
Year: 2023  
Venue: ICLR  
URL: https://openreview.net/forum?id=WE_vluYUL-X  
Key claims: Interleaving reasoning traces and actions improves tool/API-mediated problem solving.  
How it supports SIFR: Motivates explicit Thought, Action, Observation, and Result frame types.  
How it challenges SIFR: ReAct is a prompting pattern, not evidence that a new protocol is required.  
Limitations: Does not solve authorization, auditability, or cross-agent trust.  
BibTeX: `yao2023react`

Title: Toolformer: Language Models Can Teach Themselves to Use Tools  
Authors: Timo Schick et al.  
Year: 2023  
Venue: NeurIPS  
URL: https://proceedings.neurips.cc/paper_files/paper/2023/hash/d842425e4bf79ba039352da0f658a906-Abstract-Conference.html  
Key claims: Language models can learn when and how to call APIs.  
How it supports SIFR: Supports treating tool invocation as a first-class model behavior.  
How it challenges SIFR: Tool use alone does not imply the need for SIFR's full protocol stack.  
Limitations: Fixed API/tool setting; no capability security layer.  
BibTeX: `schick2023toolformer`

Title: Talk Structurally, Act Hierarchically  
Authors: Zhao Wang, Sota Moriyama, Wei-Yao Wang, Briti Gangopadhyay, Shingo Takamatsu  
Year: 2025  
Source: arXiv  
DOI: https://doi.org/10.48550/arXiv.2502.11098  
Key claims: Structured communication and hierarchical refinement improve LLM multi-agent systems.  
How it supports SIFR: Supports structured communication as a research direction.  
How it challenges SIFR: Structured communication can be implemented at prompt/application level without protocol signatures.  
Limitations: Preprint; not confirmed as peer-reviewed.  
BibTeX: `wang2025talkhier`

## Security, Identity, Provenance, and Sandboxing

Title: Zero Trust Architecture  
Authors: Scott Rose, Oliver Borchert, Stu Mitchell, Sean Connelly  
Year: 2020  
Source: NIST SP 800-207  
DOI: https://doi.org/10.6028/NIST.SP.800-207  
Key claims: Access decisions should be per-request and not rely on network location.  
How it supports SIFR: Supports capability checks for each protected action.  
How it challenges SIFR: Enterprise zero trust is broader than SIFR's prototype and requires policy infrastructure.  
Limitations: Not agent-specific.  
BibTeX: `rose2020zerotrust`

Title: Decentralized Identifiers v1.0  
Authors / org: W3C DID Working Group  
Year: 2022  
Source: W3C Recommendation  
URL: https://www.w3.org/TR/did-core/  
Key claims: Defines DID syntax, data model, DID documents, and resolution concepts.  
How it supports SIFR: Provides a future path for agent identity.  
How it challenges SIFR: v0.1 does not implement DID resolution, so it must not claim DID compliance.  
Limitations: Trust depends on DID methods and governance.  
BibTeX: `w3c2022did`

Title: Verifiable Credentials Data Model v2.0  
Authors / org: W3C Verifiable Credentials Working Group  
Year: 2025  
Source: W3C Recommendation  
URL: https://www.w3.org/TR/vc-data-model/  
Key claims: Defines a data model for issuer claims that can be cryptographically verified.  
How it supports SIFR: Future capability grants could be represented or backed by verifiable credentials.  
How it challenges SIFR: v0.1 has no VC issuance, proof, status, or revocation mechanism.  
Limitations: Requires companion proof and status specifications.  
BibTeX: `w3c2025vc`

Title: QUIC: A UDP-Based Multiplexed and Secure Transport  
Authors: Jana Iyengar, Martin Thomson  
Year: 2021  
Source: RFC 9000  
DOI: https://doi.org/10.17487/RFC9000  
Key claims: QUIC supports multiplexed streams, low-latency setup, connection migration, and integrated security.  
How it supports SIFR: Motivates future low-latency transport.  
How it challenges SIFR: QUIC is only transport; SIFR must justify its application semantics.  
Limitations: Not implemented in v0.1.  
BibTeX: `iyengar2021quic`

Title: WebAssembly Specifications and WASI Interfaces  
Authors / org: W3C WebAssembly Community Group and WASI maintainers  
Year: 2019-2025  
URLs: https://webassembly.org/specs/ and https://wasi.dev/interfaces  
Key claims: WebAssembly provides portable execution; WASI defines system interfaces.  
How it supports SIFR: Motivates future sandboxed tool execution.  
How it challenges SIFR: Sandbox security depends on runtime configuration and is not automatic.  
Limitations: Not implemented in v0.1.  
BibTeX: `w3c2019wasm`, `wasi2024interfaces`

Title: Merkle DAGs  
Authors / org: IPFS Documentation  
Year: 2025  
URL: https://docs.ipfs.tech/concepts/merkle-dag/  
Key claims: Content addressing makes nodes self-verifying against mutation.  
How it supports SIFR: Directly motivates audit-DAG CIDs.  
How it challenges SIFR: Availability and identity still require additional mechanisms.  
Limitations: SIFR v0.1 uses a local DAG, not a distributed content network.  
BibTeX: `ipfs2025merkledag`

## Prompt Injection and Latent Privacy

Title: Not What You've Signed Up For  
Authors: Kai Greshake, Sahar Abdelnabi, Shailesh Mishra, Christoph Endres, Thorsten Holz, Mario Fritz  
Year: 2023  
Source: arXiv  
DOI: https://doi.org/10.48550/arXiv.2302.12173  
Key claims: Indirect prompt injection can manipulate LLM-integrated applications via retrieved content.  
How it supports SIFR: Motivates protocol-level tool gating and auditability.  
How it challenges SIFR: Signatures and capabilities do not solve instruction/data confusion by themselves.  
Limitations: Threat landscape continues to evolve.  
BibTeX: `greshake2023indirectpi`

Title: Formalizing and Benchmarking Prompt Injection Attacks and Defenses  
Authors: Yupei Liu, Yuqi Jia, Runpeng Geng, Jinyuan Jia, Neil Zhenqiang Gong  
Year: 2024  
Source: USENIX Security / arXiv  
DOI: https://doi.org/10.48550/arXiv.2310.12815  
Key claims: Provides formalization and benchmarks for prompt injection.  
How it supports SIFR: Suggests evaluation directions for future security tests.  
How it challenges SIFR: SIFR v0.1 does not benchmark prompt injection defenses.  
Limitations: Benchmarks do not cover every agent workflow.  
BibTeX: `liu2024promptinjection`

Title: Text Embeddings Reveal (Almost) As Much As Text  
Authors: John X. Morris, Volodymyr Kuleshov, Vitaly Shmatikov, Alexander M. Rush  
Year: 2023  
Venue: EMNLP  
DOI: https://doi.org/10.18653/v1/2023.emnlp-main.765  
Key claims: Dense embeddings can reveal substantial information about source text.  
How it supports SIFR: Forces cautious treatment of TensorFrame privacy.  
How it challenges SIFR: Any latent channel must have a privacy model before deployment.  
Limitations: Attack success depends on model, text, and access assumptions.  
BibTeX: `morris2023embeddingprivacy`

Title: Shadow in the Cache  
Authors: Zhifan Luo, Shuo Shao, Su Zhang, Lijing Zhou, Yuke Hu, Chenxu Zhao, Zhihao Liu, Zhan Qin  
Year: 2026  
Source: NDSS / arXiv  
DOI: https://doi.org/10.48550/arXiv.2508.09442  
Key claims: KV caches can leak sensitive inputs under certain attacks.  
How it supports SIFR: Warns against casual KV-cache sharing claims.  
How it challenges SIFR: Future TensorFrame or latent-channel designs require serious privacy analysis.  
Limitations: Newly accepted work; deployment assumptions should be validated.  
BibTeX: `luo2026shadowcache`
