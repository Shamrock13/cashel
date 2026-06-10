import os


# Demo mode disables persistent write operations and enables hosted sample flows.
DEMO_MODE: bool = os.environ.get("CASHEL_DEMO_MODE", "false").lower() == "true"
