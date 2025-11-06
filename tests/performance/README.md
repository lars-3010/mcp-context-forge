# MCP Gateway Performance Testing

Comprehensive performance testing suite for MCP Gateway with load testing, server profiling, infrastructure testing, and baseline comparison.

## Quick Start

```bash
task install          # Install dependencies (hey)
task test            # Run standard performance test
task test-gateway-core  # Test gateway internals
task test-database   # Test database connection pool
```

Results go to `results/{profile}_{timestamp}/`, reports to `reports/`.

## Common Commands

### Basic Testing
```bash
task test            # Standard test (10K requests, 50 concurrent)
task quick           # Quick smoke test (100 requests)
task heavy           # Heavy load (50K requests, 200 concurrent)
```

### New Comprehensive Tests
```bash
task test-gateway-core    # 11 gateway core tests (health, admin API, etc.)
task test-database        # 4 database connection pool tests
task test-all-scenarios   # Run all test scenarios
```

### Server Profiles
```bash
task test-optimized       # 8 workers, 2 threads - high throughput
task test-memory          # 4 workers, 8 threads - many connections
task test-io              # 6 workers, 50 DB pool - I/O heavy
```

### Infrastructure
```bash
task test-production      # 4 instances with nginx load balancer
task test-scaling         # Test with 4 instances
task compare-postgres     # Compare PostgreSQL 15 vs 17
```

### Baseline Management
```bash
task baseline             # Save current as baseline
task compare              # Compare with baseline
task list-baselines       # List all baselines

# Save specific results
task save-baseline BASELINE=my-test RESULTS=results/medium_20241010_123456
```

### Cleanup
```bash
task clean                # Clean result files
task clean-results        # Remove all result directories
task clean-all            # Deep clean (results + baselines + reports)
```

## Available Profiles

### Load Profiles
| Profile | Requests | Concurrency | Use Case |
|---------|----------|-------------|----------|
| smoke | 100 | 5 | Quick validation |
| light | 1,000 | 10 | Fast testing |
| medium | 10,000 | 50 | Realistic load |
| heavy | 50,000 | 200 | Stress testing |

### Server Profiles
| Profile | Workers | Threads | DB Pool | Best For |
|---------|---------|---------|---------|----------|
| minimal | 1 | 2 | 5 | Dev/testing |
| standard | 4 | 4 | 20 | Balanced (default) |
| optimized | 8 | 2 | 30 | CPU-bound, high RPS |
| memory_optimized | 4 | 8 | 40 | Many connections |
| io_optimized | 6 | 4 | 50 | Database-heavy |

### Infrastructure Profiles
| Profile | Instances | PostgreSQL | nginx | Use Case |
|---------|-----------|------------|-------|----------|
| development | 1 | 17-alpine | No | Local dev |
| staging | 2 | 17-alpine | Yes | Pre-prod |
| production | 4 | 17-alpine | Yes | Production |
| production_ha | 6 | 17-alpine | Yes | High availability |

## Examples

### Find Optimal Configuration
```bash
# Test all server profiles
task test-minimal
task test-standard
task test-optimized

# Compare results, choose best cost/performance
```

### Plan Database Upgrade
```bash
# Compare PostgreSQL versions
task compare-postgres

# Or manually:
./run-advanced.sh -p medium --postgres-version 15-alpine --save-baseline pg15.json
./run-advanced.sh -p medium --postgres-version 17-alpine --compare-with pg15.json
```

### Capacity Planning
```bash
# Test different instance counts
./run-advanced.sh -p heavy --instances 1 --save-baseline 1x.json
./run-advanced.sh -p heavy --instances 4 --save-baseline 4x.json
./run-advanced.sh -p heavy --instances 8 --save-baseline 8x.json

# Compare to find optimal scaling point
```

### Regression Testing
```bash
# Before code changes
task baseline-production

# After changes
task compare

# Automatically fails if regressions detected
```

## Directory Structure

```
tests/performance/
├── Makefile              # 👈 Main entrypoint (start here)
├── README.md             # 👈 This file
├── PERFORMANCE_STRATEGY.md  # Complete testing strategy
├── config.yaml           # Configuration
│
├── run-advanced.sh       # Advanced runner with all features
├── run-configurable.sh   # Config-driven test execution
│
├── utils/
│   ├── generate_docker_compose.py  # Generate docker-compose + nginx
│   ├── compare_results.py          # Compare baselines
│   ├── baseline_manager.py         # Manage baselines
│   ├── report_generator.py         # HTML reports
│   ├── check-services.sh           # Health checks
│   └── setup-auth.sh               # JWT authentication
│
├── scenarios/
│   ├── tools-benchmark.sh          # MCP tools tests
│   ├── resources-benchmark.sh      # MCP resources tests
│   ├── prompts-benchmark.sh        # MCP prompts tests
│   ├── gateway-core-benchmark.sh   # 11 gateway core tests (NEW)
│   └── database-benchmark.sh       # 4 DB connection tests (NEW)
│
├── results/              # Test results (gitignored)
│   └── {profile}_{timestamp}/
├── baselines/            # Saved baselines (gitignored)
└── reports/              # HTML reports (gitignored)
```

## Advanced Usage

### Custom Results Location
```bash
# Override default results directory
RESULTS_BASE=/mnt/storage/perf make test
```

### Direct Runner
```bash
# Full control with run-advanced.sh
./run-advanced.sh -p medium \
  --server-profile optimized \
  --infrastructure production \
  --postgres-version 17-alpine \
  --instances 4 \
  --save-baseline prod_baseline.json
```

### Generate Docker Compose
```bash
# Generate custom docker-compose with nginx load balancer
./utils/generate_docker_compose.py \
  --infrastructure production \
  --server-profile optimized \
  --instances 4 \
  --output docker-compose.prod.yml

# Creates:
# - docker-compose.prod.yml (4 gateway instances + nginx)
# - nginx.conf (round-robin load balancer)
```

## Output

### Test Results
```
results/medium_standard_20241010_123456/
├── tools_benchmark_list_tools_medium_*.txt  # hey output
├── gateway_admin_list_tools_medium_*.txt    # Gateway tests
├── db_pool_stress_100_medium_*.txt          # DB tests
├── system_metrics.csv                        # CPU, memory
├── docker_stats.csv                          # Container stats
├── prometheus_metrics.txt                    # Metrics snapshot
└── gateway_logs.txt                          # Application logs
```

### Baselines
```json
{
  "version": "1.0",
  "created": "2025-10-10T00:11:09.675032",
  "metadata": {
    "profile": "medium",
    "server_profile": "optimized"
  },
  "results": {
    "tools_list_tools": {
      "rps": 822.45,
      "avg": 12.1,
      "p95": 18.9,
      "p99": 24.5,
      "error_rate": 0.0
    }
  }
}
```

## Configuration

Edit `config.yaml` to customize:
- Load profiles (requests, concurrency, timeouts)
- Server profiles (workers, threads, DB pool sizes)
- Infrastructure profiles (instances, PostgreSQL settings)
- SLO thresholds
- Monitoring options

## Troubleshooting

### Services Not Starting
```bash
task check                    # Check health
docker-compose logs gateway   # View logs
```

### Authentication Failed
```bash
./utils/setup-auth.sh         # Regenerate token
source .auth_token            # Load token
```

### Tests Timeout
```bash
# Tests now have proper timeouts:
# - make test: 600s (10 minutes)
# - make heavy: 1200s (20 minutes)
```

### Cleanup
```bash
task clean-results            # Remove old test runs
task clean-all                # Deep clean everything
```

## What's New (v2.1)

✅ **Timeout Handling** - Tests won't be killed prematurely
✅ **Graceful Shutdown** - Saves partial results on interrupt
✅ **Gateway Core Tests** - 11 new tests for gateway internals
✅ **Database Tests** - 4 new tests for connection pool behavior
✅ **Results Organization** - All results in `results/` subdirectory
✅ **nginx Load Balancer** - Auto-generated for multi-instance tests
✅ **Better Cleanup** - New make targets for cleanup

## Quick Reference

```bash
# List everything
task help                     # Show all commands
task list-profiles            # Show load/server/infra profiles
task list-baselines           # Show saved baselines

# Testing
task test                     # Standard test
task test-gateway-core        # Gateway tests (NEW)
task test-database            # DB tests (NEW)

# Comparison
task baseline                 # Save baseline
task compare                  # Compare with baseline

# Cleanup
task clean                    # Clean files
task clean-results            # Clean directories
```

## Documentation

- **This file** - Quick start and common commands
- **[PERFORMANCE_STRATEGY.md](PERFORMANCE_STRATEGY.md)** - Complete testing strategy, server profile guide, automation guide

---

**Ready?** Run `task test` or `task help`
