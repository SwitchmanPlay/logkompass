# Local model, hosted model, or both

The digest is the only place a model is involved, and it is optional: without any
provider the deterministic template still produces the same five lines. So this choice is
about prose quality and about what you can claim on a CV, not about whether the tool works.

## Recommendation

Configure **both**, local first. It costs nothing extra and it is the honest answer to
"what happens when your workstation is off".

```toml
[[llm.providers]]           # 1st: your own hardware
name = "local-qwen3"
base_url = "http://100.x.y.z:8081/v1"
model = "qwen3-27b"
extra_body = { chat_template_kwargs = { enable_thinking = false } }

[[llm.providers]]           # 2nd: free hosted, only used when the first is unreachable
name = "openrouter-free"
base_url = "https://openrouter.ai/api/v1"
model = "meta-llama/llama-3.3-70b-instruct:free"
api_key = "env:OPENROUTER_API_KEY"
```

A provider whose API key env var is missing is marked unavailable and skipped with a
reason, so the same config file works on a machine that has no key. Which provider
answered is stored per digest in `digests.path` (`local_llm`, `cloud_llm`,
`template_fallback`), so the fallback is a data point instead of a surprise.

## Three deployment shapes

### A. Server calls your workstation (local primary)

The VPS reaches your machine over Tailscale or WireGuard and uses the 27B model you
already run on port 8081.

- Nothing leaves your hardware. Strongest privacy claim, and true, not marketing.
- Best prose, because a 27B model beats a small hosted free tier at summarising.
- Needs a tunnel, and the workstation has to be awake at 07:05. Install Tailscale on both
   sides and use the `100.x.y.z` address as `base_url`. Never expose port 8081 publicly.

### B. Workstation pulls the aggregate (local, no tunnel)

The VPS only produces JSON. Your machine fetches it over SSH and runs the digest locally:

```bash
bash scripts/pc_digest.sh danya@<public-ip> 2242 2026-09-20
```

- No inbound path to your model at all, no VPN to maintain.
- Manual or driven by a local scheduler, and Telegram delivery moves to your machine.
- Good default if you dislike tunnels. `--no-store` keeps the server database clean.

### C. Server calls a hosted free model (cloud primary)

- Fully unattended, works while everything of yours is powered off.
- The aggregate leaves your infrastructure. It contains attacker IPs, counts, countries,
  and your own usernames from successful logins. Set `mask_ips = true` to truncate IPs
  first. Free tiers also usually train on your data, and rate limits change without notice.
- Reasonable as the second provider, weak as the only one.

## Running the local model

With llama.cpp:

```bash
llama-server -m Huihui-Qwen3-27B-IQ4_XS.gguf --host 0.0.0.0 --port 8081 --ctx-size 8192
```

The digest prompt is small, roughly 1 to 2k tokens of JSON in and 150 out, so an 8k
context is plenty and IQ4_XS is fine. Bind to the Tailscale interface rather than
`0.0.0.0` if the machine is on an untrusted network.

**Qwen3 thinking mode.** Qwen3 emits `<think>` blocks by default, which wastes tokens and
breaks the five-line contract. Two defences, both already in place:
`extra_body.chat_template_kwargs.enable_thinking = false` in the request, and
`strip_thinking()` on the response for servers that ignore the switch.

## Prompt and guards

The system prompt asks for exactly five lines, plain text, max 30 words each, and forbids
numbers that are not in the JSON. `temperature = 0.0`. Then the output is checked:

1. Five usable lines after stripping markdown bullets.
2. Every IPv4 in the answer appears in the aggregate. Otherwise the answer is thrown away.
3. On any failure the template writes the digest and the message carries a label.

A 27B model at IQ4_XS occasionally rounds a number or merges two lines. The guards are why
that degrades into a boring digest instead of a wrong one. Guard trips and provider errors
are surfaced in the `digest` command output, so a quiet regression is visible.
