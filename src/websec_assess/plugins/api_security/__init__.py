"""API security plugins.

Implemented: openapi_parser (parses specs found by
content_discovery.api_endpoint_id), graphql_discovery (introspection probe).
REST endpoint enumeration itself lives in content_discovery.api_endpoint_id
-- no need to duplicate it here.

Documented extension point, not implemented: api_auth_review (per-endpoint
"is auth actually enforced" review needs either valid test credentials or
deep contextual knowledge of the API's intended access model -- doing this
generically and unauthenticated risks both false positives and false
negatives, so it's left for an engagement-specific plugin rather than
shipped as a guess). See docs/plugin_development.md.
"""
