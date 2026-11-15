# Calling the API directly

```bash
# 1. Get a key (25 free calls)
curl -X POST https://slfguardian.com/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com"}'

# 2. Is this package real and safe?
curl -X POST https://slfguardian.com/v1/package \
  -H "Authorization: Bearer $SLF_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"langchain-helper-utils","ecosystem":"npm"}'

# 3. Can this command be undone?
curl -X POST https://slfguardian.com/v1/command \
  -H "Authorization: Bearer $SLF_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"command":"git push --force origin main"}'
```

Machine-readable description of every endpoint:
<https://slfguardian.com/openapi.json>
