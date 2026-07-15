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
#
# Assign, do NOT setdefault: the suite asserts against these exact values
# (discovery tests POST TEST_SECRET and expect 200), so an ambient
# MAIL2RSS_SECRET — e.g. the CI workflow's `env:` block — would make every
# authorized request fail with 401 while the app waits for a different secret.
#
# TEST_SECRET is a real, canonical machine-generated secret (26 chars, a-z2-7):
# validate_secret() must accept it, or importing src.settings would exit(1).
TEST_SECRET = "o2au6sdynfj7xokdurkazuwhoy"
os.environ["FASTMAIL_API_TOKEN"] = "test-token"
os.environ["MAIL2RSS_SECRET"] = TEST_SECRET
os.environ["BASE_URL"] = "https://rss.example.test"
