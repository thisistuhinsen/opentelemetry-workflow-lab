# Public MCP session-id correction

`shop story mcp-session-id` automatically materializes the pinned public source and applies the shipped Apache-2.0 query correction. It builds one small layer over the immutable official MCP image. The generated build context contains only its Dockerfile and the qualified public `src/shared/tools.py`; it does not send the full source tree to Docker.

The case compares one synthetic shopper's HTTP cart with the MCP get_cart result. The original and corrected variants remain separate, and each explicit replay gets a fresh shop and shopper. The actual build identity, inputs and results are saved in the host evidence folder. No derivative image is published by this repository.