# OpenTelemetry Workflow Lab

Run a pinned Astronomy Shop locally, compare checkout and MCP behavior, and inspect each run's logs and traces in a local visual viewer. The hosted Linux qualification also runs one synthetic Chromium checkout and a read-only Valkey snapshot join.

## Start here

Install Python 3.12+, Git, and Docker with the Compose plugin. Start Docker using Linux containers. The sample uses linux/amd64 images; budget about 8 GB for the Docker VM and space for the selected images. It binds only localhost ports 8080 and 8011. Windows, macOS and Linux are supported by the launcher. CI runs the process and watcher lifecycle contract tests on all three platforms; the full Docker story run remains a single Ubuntu job. These checks do not establish that Docker Desktop is running or qualify a local full-stack run on each desktop OS.

From this folder, use `shop.cmd` on Windows or `./shop` on Linux/macOS:

```text
shop.cmd cases
shop.cmd start normal
shop.cmd story normal
shop.cmd story cart-failure
shop.cmd story payment-unreachable
shop.cmd story mcp-session-id
shop.cmd story shared-cart-conflict
shop.cmd reset
shop.cmd replay
shop.cmd view
shop.cmd stop
shop.cmd clean
```

The optional pinned demo-agent cassette path is explicit and separate from the normal catalog:

```text
python public/shop.py setup --agent-replay
python public/shop.py start normal
python public/shop.py agent-replay
python public/shop.py stop
```

This builds the optional public agent from the pinned source, uses the existing `azure/gpt-5.5` cassette with a local replay-only overlay (`vcrpy==8.3.0`, record mode `none`, exact-body threshold `1.0`), supplies a dummy key and an unreachable loopback model URL, mounts the cassette read-only, and places the agent on an internal-only network. The command verifies those boundaries before sending the one documented list-products prompt; a cassette miss fails locally and is never recorded or retried. Its result is labeled `FIXTURE REPLAY`, not live model behavior. The upstream default remains `new_episodes`; the overlay and its digest are recorded per prepared world. Agent image construction may download the public dependencies from the pinned requirements lock, but the runtime cannot reach an external model endpoint.

`start` automatically acquires the pinned public source, prepares isolated configuration, downloads immutable upstream images, and checks the catalog and MCP endpoints. It does not buy anything. The MCP case automatically builds one small public query-correction layer over its immutable upstream image. Setup progress and logs appear in the run viewer.

`story` executes the selected case once with a new fictional shopper. Changing stories switches to a fresh isolated shop. `reset` starts a fresh shop without a purchase. `replay` performs the case in another fresh shop with another shopper; it never retries an uncertain old purchase. All purchases and payment/shipping services here are simulated by the public demo. Never supply real personal or payment data.

## Cases and expected observations

| Case | What happens | Expected observation |
|---|---|---|
| normal | Add one item, then check out | Order response and empty cart |
| cart-failure | Enable the demo cart-clear fault, then check out | Order response but the item remains; this demonstrates the fault |
| payment-unreachable | Enable the demo payment-unavailable flag | Exactly one checkout request, an error response without an order, and an independently read retained cart; CI also joins the synthetic shopper to a positive checkout error span |
| mcp-session-id | Seed distinct carts for two synthetic shoppers and read both through HTTP and MCP | Both projections match per shopper and remain distinct |
| shared-cart-conflict | Launch two sequential clients with harness-only actor labels against one synthetic cart; actor A adds an item, actor B clears it | Ordered raw responses and same-user readback show the later clear; this is not an overlap/concurrency or product-authentication test |

A case passes when its stated observation is reproduced. A harmful case passing does not mean its business behavior is correct. These observations do not establish settlement, fulfillment, durable deduplication or safe retry. A failed or ambiguous attempt remains recorded.

Unavailable, malformed, stale-but-well-formed, or mismatched-user readbacks cannot make a failed case `OBSERVED` or authorize a reset. Empty carts that omit `userId` remain explicitly `NOT_ECHOED_FOR_EMPTY_CART`. The harness also tests allowed operations on its captured Compose target and denial when target identity drifts. That is harness-scope enforcement, not application authorization. CI stops and restarts the shared-cart-conflict project, rechecks the same synthetic cart, then resets to a fresh isolated shop and replays each case with fresh identities; it compares stable semantics while excluding project, shopper, time, and inherently variable race outcomes.

The catalog has five business/runtime stories and one timing diagnostic. `shared-cart-conflict` records sequential conflicting intents; `shared-cart-overlap-diagnostic` records whether client request windows intersect and may report either `OBSERVED` or `NOT_OBSERVED`. That diagnostic does not establish overlap inside a service handler. CI also performs a separate real Chromium checkout before the catalog, then correlates allowlisted checkout, payment and email spans for its synthetic order and compares the API cart with a read-only Valkey hash snapshot. These observations describe the pinned demo only: spans are not an independent journal, and neither spans nor a cart snapshot prove settlement, fulfillment, external email delivery or application authorization.

## Coverage and limits

| Requirement kind | Public implementation and evidence | Limit |
|---|---|---|
| Browser checkout and successful simulated flow | Hosted Linux CI uses Chromium against the pinned local frontend, one fictional shopper and one checkout dispatch; it checks the receipt page, HTTP order response, cart API readback, matching demo service spans and direct Valkey snapshot. | This is a demo observation, not a real payment, order ledger or delivered email. Local CLI `story normal` remains API-driven. |
| Harmful success-shaped cart failure | `cart-failure` expects an order response while the cart item remains. | The deliberately selected demo fault is not a production failure-mode guarantee. |
| Observer unavailable, stale or malformed | Unit controls require `UNKNOWN` for unavailable, wrong-shopper, stale, malformed or misbound Valkey observations; campaign logic blocks reset when direct readback is unknown or contradicted. | The negative failure modes are fault-injected tests; CI does not deliberately take Valkey offline during a business story. |
| Two clients and shared state | `shared-cart-conflict` runs separately launched clients sequentially against one cart and preserves ordered responses/readback. The timing diagnostic separately records measured client-window overlap or non-overlap. | Actor labels are harness labels, not app authorization. Client-window overlap does not prove server-handler interleaving. |
| Allowed and denied harness scope | Source/command-boundary tests accept the selected Compose project and reject target drift or unrelated scope. | A harness denial is not an application authorization test. |
| Same-world persistence and repeatability | CI restarts the shared-cart project and checks the same cart, then resets and replays each catalog story in a fresh project/shopper namespace with stable-semantic comparison. | It does not establish durable behavior across host or Docker-daemon loss. |
| MCP channel | The real MCP client initializes, lists tools, mutates a second synthetic shopper with `add_to_cart`, reads carts, and compares HTTP plus direct Valkey state. | This exercises the pinned local MCP service, not a third-party agent host. |
| Correlated payment/order/email observations | The Chromium checkout is joined to allowlisted checkout, payment-charged and email-send OTel spans by synthetic user/order/trace identity. | These are application-emitted spans, not an independent payment/order/email journal, settlement receipt, or delivery confirmation. The pinned demo does not supply that independent journal; this stronger requirement remains open. |
| Demo-agent endpoint / cassette replay | The Docker campaign exercises the pinned demo-agent HTTP endpoint with `Show all available products in the store.` against cassette SHA-256 `40a69e2353678db7ea7cb69baf5c1626097315cd1c4cdf33d66bff6496506acd`. It records the overlay digest, VCR version, exact-body threshold, tool turn and returned-answer digest. The replay-only overlay SHA-256 is `a2396ca2c5f1f8f718ad178d4c6ee941a723f87bd6ba2191ec9f45e6d9f25ae2`; it forces VCR record mode `none`, and the CI precheck proves an HTTPX cassette miss is rejected without reaching a network response. | This is `FIXTURE_REPLAY`, not live inference. No real API key, external model call, cassette recording, or paid provider is used. The overlay is an explicit testbed shim over upstream's `new_episodes` default, not upstream behavior. |
| No-defect source-refactor control | Kept outside the runtime story catalog; this repository's contract is the public demo/testbed, not an agent implementation evaluator. | A generic agent patch/equivalence evaluation belongs in the consuming evaluator, not in a fabricated demo business scenario. No runtime effect-parity claim is made. |

There are five business/runtime stories and one timing diagnostic, not six distinct business stories. Observer-failure checks, harness allow/deny, restart/reset/replay and the no-defect refactor are controls or procedures, not additional business cases. The no-defect item-plus-shipping helper refactor is kept outside this runtime catalog because this repository tests the public demo; it does not evaluate an agent's source patch or claim before/after effect parity. The real Chromium checkout, direct Valkey reads and optional agent cassette replay run only in the GitHub-hosted Linux Docker job. Native Windows/macOS/Apple Silicon CI covers Python launcher/lifecycle contracts; this repository has not qualified Docker Desktop engines on Windows or macOS.

## Evidence survives Docker cleanup

Each command opens `evidence/index.html` automatically, except in CI or with `--no-browser`. It is a local, interactive page: filter runs, select a run, inspect phases and stdout/stderr, and open result JSON or input snapshots. It works directly from disk without Docker or a web server. Command output streams to host files, and a companion captures service logs while the shop runs. Application traces are exported directly to the same host evidence tree.

```text
evidence/
  index.html
  runs/<run-id>/run.json
  runs/<run-id>/events.jsonl
  runs/<run-id>/result.json
  runs/<run-id>/commands/
  runs/<run-id>/inputs/
  telemetry/<shop-project>/traces.jsonl
```

`stop` retains shop data. `clean` removes only shops recorded in this launcher's state folder, including their volumes and networks. Neither deletes evidence. Copy the evidence folder wherever you keep experiment records; Docker's image/volume storage is not its authority. Runtime files are ignored by Git. The public CI uploads its evidence as a finite-retention artifact; download it for permanent retention.

For another drive or ports, place global options before the command:

```text
python public/shop.py --state-dir D:\testbed\state --evidence-dir D:\testbed\evidence setup --http-port 18080 --mcp-port 18011
python public/shop.py --state-dir D:\testbed\state start
python public/shop.py --state-dir D:\testbed\state story normal
```

Use `python public/shop.py --help` and `python public/shop.py setup --help` for details. The selected Docker context is captured during setup and reused; later commands do not silently switch engines.

## Checks and extension

```text
python -m unittest discover -s public/tests -v
python public/ci_smoke.py --self-test
python public/ci_smoke.py --agent-replay
```

The last command runs one real browser checkout, the catalog cases, fresh reset and replay, and the pinned demo-agent cassette replay, then verifies scoped cleanup and retained evidence. It requires pinned Playwright/Chromium and the pinned public agent build dependencies in the CI job. Agent replay uses an internal-only Docker network, dummy credentials and an unreachable loopback model URL; the cassette and overlay are captured as bound inputs. Use a fresh state folder; it refuses to replay an unfinished campaign. CI uses one Linux Docker job with immutable action pins and no registry write credentials. A required-image census distinguishes cold downloads from cached runs; local reset alone is not cold reconstruction.

Add case metadata in `public/stories.json`. Supported actions and expected-outcome validators are deliberately explicit in `public/shop.py`; add a discriminating validator and tests for new behavior. The CLI and CI read the same catalog. Keep source/image pins, public patch hashes, source-integrity inventory and provenance records consistent. Do not add secrets or private evidence to the repository or an image build context.

## Troubleshooting

If startup fails, open the failed run's stderr and service logs. Check Docker is running, localhost ports are free, and the host has enough memory/disk. Backend services use an internal bridge; only the browser and MCP entrypoints join the loopback publishing network. The launcher chooses non-overlapping project subnets without pruning other networks. Case faults are expected only in their selected story. Source/config changes are rejected rather than silently reused; prepare a fresh source/state folder after intentional changes.

The public demo is licensed under Apache-2.0. See [LICENSE](public/LICENSE) and [NOTICE](public/NOTICE). Upstream source is pinned to OpenTelemetry Demo `2c4be61741536937f1486ecaf74f44dbfd15d707`; application image records contain upstream registry provenance claims, not verified signatures. This repository does not publish or retag those upstream images.
