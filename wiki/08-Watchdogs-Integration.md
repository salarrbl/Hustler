# Watchdogs Integration

Hustler can connect to Watchdogs MongoDB to import and organize targets as **Platform → Program → Assets**.

## Overview

Watchdogs is a continuous subdomain recon tool. Hustler's integration allows you to:
- Fetch **live subdomains** (HTTP responses with valid status codes)
- Organize targets by platform and program
- Filter by specific platforms or programs
- One-time fetch (not continuous)
- Skip already-imported targets with `--new-only`

## Configuration

Enable Watchdogs integration in `config.yaml`:

```yaml
watchdogs:
  enabled: true                    # Must be true to use
  mongo_uri: "mongodb://localhost:27017"  # Watchdogs DB URI
  database: "watchdogs"            # Watchdogs database name
  sync_interval: "1h"              # (Not used - one-time fetch)
  field_mapping:
    collection: "http"             # Uses HTTP collection for live subs
    domain_field: "subdomain"
    root_domain_field: "root_domain"
    status_field: "status_code"
    # Optional: if Watchdogs stores program/platform data
    # program_field: "program"
    # platform_field: "platform"
```

## Commands

### 1. Fetch Live Subdomains

```bash
# Fetch all live subdomains from Watchdogs
hustler watchdogs fetch

# Fetch only from a specific platform
hustler watchdogs fetch --platform hackerone
hustler watchdogs fetch --platform bugcrowd
hustler watchdogs fetch --platform intigriti

# Fetch only from a specific program
hustler watchdogs fetch --program "Google"
hustler watchdogs fetch --program "Shopify"

# Fetch only new targets (not already in Hustler)
hustler watchdogs fetch --new-only

# Combine filters
hustler watchdogs fetch --platform hackerone --program "Google"
hustler watchdogs fetch --platform bugcrowd --new-only

# Show hierarchy after fetch
hustler watchdogs fetch --tree
```

### 2. View Target Hierarchy

```bash
# Show Platform → Program → Assets tree (default 7 per program)
hustler watchdogs tree

# Show with custom limit
hustler watchdogs tree --limit 10
hustler watchdogs tree --limit 20

# Show all (no limit)
hustler watchdogs tree --limit 0

# Filter by platform
hustler watchdogs tree --platform hackerone
hustler watchdogs tree --platform bugcrowd --limit 10
```

### 3. List Platforms

```bash
# Show all platforms with counts
hustler watchdogs platforms

# Example output:
# Available Platforms:
# ───────────────────
#   📁 hackerone: 5 programs, 234 assets
#   📁 bugcrowd: 3 programs, 156 assets
#   📁 intigriti: 2 programs, 89 assets
#
#   Total: 3 platforms, 10 programs, 479 assets
```

### 4. List Programs

```bash
# Show all programs
hustler watchdogs programs

# Filter by platform
hustler watchdogs programs --platform hackerone
hustler watchdogs programs --platform bugcrowd

# Example output:
# Available Programs:
# ───────────────────
# [hackerone]
#   📂 Google: 45 assets
#   📂 Shopify: 67 assets
#   📂 Uber: 23 assets
#
# [bugcrowd]
#   📂 Tesla: 34 assets
#   📂 Starbucks: 12 assets
```

### 5. List Assets

```bash
# Show 7 assets per program (default)
hustler watchdogs assets

# Show more assets
hustler watchdogs assets --limit 10
hustler watchdogs assets --limit 20

# Show all (no limit)
hustler watchdogs assets --limit 0

# Show only counts (not actual targets)
hustler watchdogs assets --count

# Filter by platform
hustler watchdogs assets --platform hackerone

# Filter by program
hustler watchdogs assets --program "Google"

# Combine filters
hustler watchdogs assets --platform hackerone --program "Google" --limit 5
```

## Output Examples

### Tree View with Limit
```
📊 Target Hierarchy (2 platforms, 5 programs, 156 assets)
═══════════════════════════════════════════════════════════

📁 hackerone (2 programs, 89 assets)

  📂 Google (45)
      ├── sub1.google.com
      ├── sub2.google.com
      ├── sub3.google.com
      ├── sub4.google.com
      ├── sub5.google.com
      ├── sub6.google.com
      ├── sub7.google.com
      └── ... 38 more targets

  📂 Shopify (44)
      ├── shop1.shopify.com
      ├── shop2.shopify.com
      ...

📁 bugcrowd (3 programs, 67 assets)
  ...
```

### Fetch with Summary
```
✅ Fetch completed!
   Platforms: 2
   Programs: 5
   Total Assets: 156
   New Assets: 23
   Skipped: 133
```

## Understanding `--new-only`

The `--new-only` flag prevents importing targets that already exist in Hustler:

```bash
# Step 1: First fetch for Google (no --new-only)
hustler watchdogs fetch --program "Google"
# → Adds all Google subdomains to Hustler

# Step 2: Fetch again for Google with --new-only
hustler watchdogs fetch --program "Google" --new-only
# → Skips ALL Google subs (they already exist!)

# Step 3: Fetch different program with --new-only
hustler watchdogs fetch --program "Shopify" --new-only
# → Adds only NEW Shopify subs (not already in Hustler)

# Step 4: Fetch all with --new-only
hustler watchdogs fetch --new-only
# → Only adds subs that DON'T exist anywhere in Hustler
```

**Key Point:** `--new-only` is **global** - it checks if a subdomain exists anywhere in Hustler, not just within that specific program.

## Data Organization

Targets are organized as:

```
Platform (e.g., hackerone)
└── Program (e.g., Google)
    └── Assets/Targets (e.g., subdomains)
        ├── sub1.google.com
        ├── sub2.google.com
        └── ...
```

Each target includes:
- `domain` - The subdomain
- `root_domain` - Parent domain
- `platform` - Bug bounty platform
- `program_id` - Reference to program
- `status_code` - HTTP status
- `title` - Page title
- `technologies` - Detected tech stack
- `ports` - Open ports
- `cdn` - CDN provider

## Tips

1. **Start Fresh:** Run without `--new-only` first time, then use `--new-only` for incremental updates

2. **Use Filters:** When you have many targets, filter by platform/program:
   ```bash
   hustler watchdogs fetch --platform hackerone --new-only
   ```

3. **Check Before Fetch:** View what's available first:
   ```bash
   hustler watchdogs platforms
   hustler watchdogs programs --platform hackerone
   hustler watchdogs tree --limit 10
   ```

4. **Export to File:** Redirect output to save lists:
   ```bash
   hustler watchdogs assets --platform hackerone --limit 0 > targets.txt
   ```

## Troubleshooting

### "Watchdogs integration is disabled"
Set `watchdogs.enabled: true` in `config.yaml`

### "Failed to connect to Watchdogs MongoDB"
- Verify Watchdogs MongoDB is running
- Check `mongo_uri` in config matches Watchdogs DB location
- Ensure network connectivity to the Watchdogs server

### "No targets found"
- Run `hustler watchdogs platforms` to verify connection
- Check if Watchdogs has data in the `http` collection
- Verify `field_mapping.collection` matches Watchdogs schema
