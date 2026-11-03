# OpenTelemetry Workflow Lab

Run a pinned Astronomy Shop locally, compare checkout and MCP behavior, and inspect each run's logs and traces in a local visual viewer.

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
shop.cmd reset
shop.cmd replay
shop.cmd view
shop.cmd stop
shop.cmd clean
```

`start` automatically acquires the pinned public source, prepares isolated configuration, downloads immutable upstream images, and checks the catalog and MCP endpoints. It does not buy anything. The MCP case automatically builds one small public query-correction layer over its immutable upstream image. Setup progress and logs appear in the run viewer.

`story` executes the selected case once with a new fictional shopper. Changing stories switches to a fresh isolated shop. `reset` starts a fresh shop without a purchase. `replay` performs the case in another fresh shop with another shopper; it never retries an uncertain old purchase. All purchases and payment/shipping services here are simulated by the public demo. Never supply real personal or payment data.

## Cases and expected observations

| Case | What happens | Expected observation |
|---|---|---|
| normal | Add one item, then check out | Order response and empty cart |
| cart-failure | Enable the demo cart-clear fault, then check out | Order response but the item remains; this demonstrates the fault |
| payment-unreachable | Enable the demo payment-unavailable flag | Error response and retained cart |
| mcp-session-id | Read one shopper's cart through HTTP and MCP | Matching item identity and quantity |

A case passes when its stated observation is reproduced. A harmful case passing does not mean its business behavior is correct. These observations do not establish settlement, fulfillment, durable deduplication or safe retry. A failed or ambiguous attempt remains recorded.

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
python public/ci_smoke.py
```

The last command runs the real catalog cases, fresh reset and replay, then verifies scoped cleanup and retained evidence. Use a fresh state folder; it refuses to replay an unfinished campaign. CI uses one Linux job with immutable action pins and no registry write credentials. A required-image census distinguishes cold downloads from cached runs; local reset alone is not cold reconstruction.

Add case metadata in `public/stories.json`. Supported actions and expected-outcome validators are deliberately explicit in `public/shop.py`; add a discriminating validator and tests for new behavior. The CLI and CI read the same catalog. Keep source/image pins, public patch hashes, source-integrity inventory and provenance records consistent. Do not add secrets or private evidence to the repository or an image build context.

## Troubleshooting

If startup fails, open the failed run's stderr and service logs. Check Docker is running, localhost ports are free, and the host has enough memory/disk. Backend services use an internal bridge; only the browser and MCP entrypoints join the loopback publishing network. The launcher chooses non-overlapping project subnets without pruning other networks. Case faults are expected only in their selected story. Source/config changes are rejected rather than silently reused; prepare a fresh source/state folder after intentional changes.

The public demo is licensed under Apache-2.0. See [LICENSE](public/LICENSE) and [NOTICE](public/NOTICE). Upstream source is pinned to OpenTelemetry Demo `2c4be61741536937f1486ecaf74f44dbfd15d707`; application image records contain upstream registry provenance claims, not verified signatures. This repository does not publish or retag those upstream images.
