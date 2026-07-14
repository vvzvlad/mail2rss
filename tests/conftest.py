import os
import time

# Force UTC so date assertions are deterministic regardless of the host TZ. This
# is a lesson from a sibling project where naive datetimes leaked and a container
# TZ change silently shifted every date (SPEC.md §11, §14.1). Set it before any
# datetime work happens.
os.environ["TZ"] = "UTC"
time.tzset()

# Provide the required credentials BEFORE any test module imports src.settings
# (Settings() is instantiated at import time and would otherwise fail at startup).
# In CI the same variables are injected via the workflow's `env:` block.
#
# TEST_SECRET is a real, canonical machine-generated secret (26 chars, a-z2-7):
# validate_secret() must accept it, or importing src.settings would exit(1).
TEST_SECRET = "o2au6sdynfj7xokdurkazuwhoy"
os.environ.setdefault("FASTMAIL_API_TOKEN", "test-token")
os.environ.setdefault("MAIL2RSS_SECRET", TEST_SECRET)
os.environ.setdefault("BASE_URL", "https://rss.example.test")
