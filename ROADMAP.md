# FluxCD Helm Upgrader - Development Roadmap

## Overview

This roadmap outlines the planned improvements and enhancements for the FluxCD Helm Upgrader project. The analysis identified several areas for improvement across security, reliability, observability, testing, and feature completeness.

## 🔴 Critical Issues (Must Fix)

### 1. Missing Essential Files ✅ **COMPLETED**
- **Issue**: `.gitignore` and `.dockerignore` files are referenced in README but don't exist
- **Impact**: Development workflow incomplete, potential security issues
- **Solution**: Create proper `.gitignore` and `.dockerignore` files

### 2. Inconsistent Image Registry References ✅ **COMPLETED**
- **Issue**: Mixed references between `kenchrcum/fluxcd-helm-upgrader` and `ghcr.io/kenchrcum/fluxcd-helm-upgrader`
- **Impact**: Confusion in deployment, potential pull failures
- **Solution**: Standardize on `ghcr.io/kenchrcum/fluxcd-helm-upgrader` throughout

### 3. Hardcoded GitHub RSA Key ✅ **COMPLETED**
- **Issue**: GitHub's SSH host key is hardcoded in `main.py` (line 308)
- **Impact**: Will break when GitHub rotates keys, security risk
- **Solution**: Implement dynamic key fetching or use SSH keyscan

## 🟡 High Priority (Should Fix)

### 4. Nova Integration ✅ **COMPLETED**
- **Issue**: Manual Helm repository scanning was limited and complex
- **Impact**: Incomplete chart detection, missing OCI support, manual version checking
- **Solution**: ✅ **IMPLEMENTED** - Full Nova CLI integration:
  - Leverages Fairwinds Nova for comprehensive Helm chart scanning
  - Supports both traditional and OCI-based Helm releases
  - JSON output processing for automated updates
  - Simplified architecture with external scanning tool

### 5. RBAC Security Enhancement ✅ **COMPLETED**
- **Issue**: Cluster-wide RBAC when namespace-scoped might suffice for most use cases
- **Impact**: Over-privileged access, security risk in multi-tenant clusters
- **Solution**: ✅ **ALREADY IMPLEMENTED** - Option for namespace-scoped RBAC with `rbac.clusterWide: false`

### 5. Health Checks Missing ✅ **COMPLETED**
- **Issue**: No liveness/readiness probes in Kubernetes manifests
- **Impact**: Poor Kubernetes integration, no failure detection
- **Solution**: ✅ **IMPLEMENTED** - Added health check endpoints (`/health`, `/ready`) and probes

### 6. Single Point of Failure ✅ **RESOLVED**
- **Issue**: Default single replica configuration
- **Impact**: Service unavailable during pod restarts, rolling updates
- **Solution**: **DESIGN DECISION** - Single replica is acceptable for this use case:
  - Application creates GitHub PRs which are manually reviewed and merged
  - Brief downtime during pod restarts is acceptable (seconds to minutes)
  - Avoids complexity of state management, distributed locking, and coordination
  - Resource limits and health checks provide sufficient reliability

## 🟢 Medium Priority (Nice to Have)

### 7. Testing Infrastructure ✅ **COMPLETED**
- **Issue**: No test files, CI/CD testing, or validation
- **Impact**: Code quality issues, regressions not caught
- **Solution**: ✅ **IMPLEMENTED** - Added comprehensive testing infrastructure:
  - ✅ Unit tests for core functions (config, version parsing, GitHub utils, manifest utils)
  - ✅ Integration tests for Kubernetes operations
  - ✅ Test runner script with coverage reporting
  - ✅ pytest configuration with 80% coverage requirement
  - ❌ GitHub Actions CI/CD pipeline (excluded per request)

### 8. Monitoring and Observability ✅ **COMPLETED**
- **Issue**: No metrics, monitoring, or alerting
- **Impact**: No visibility into application health or performance
- **Solution**: ✅ **IMPLEMENTED** - Added comprehensive monitoring and observability:
  - ✅ Prometheus metrics endpoint (`/metrics`) with detailed metrics
  - ✅ Structured logging with JSON format support
  - ✅ Alerting rules for failures and performance issues
  - ✅ ServiceMonitor and PrometheusRule templates for easy integration

### 9. OCI Registry Support ✅ **COMPLETED**
- **Issue**: OCI HelmRepository type detected but not supported
- **Impact**: Limited compatibility with modern Helm repositories
- **Solution**: ✅ **IMPLEMENTED** - Full OCI registry support with chartRef structure:
  - Automatic detection of OCI-based HelmReleases
  - OCIRepository manifest updates instead of HelmRelease updates
  - AppVersion inspection for stability assessment
  - Enhanced PR descriptions with OCI information
  - Comprehensive RBAC for OCIRepository access

### 10. Configuration Validation ✅ **COMPLETED**
- **Issue**: Limited validation of configuration values
- **Impact**: Runtime failures due to misconfiguration
- **Solution**: ✅ **IMPLEMENTED** - Added comprehensive configuration validation:
  - ✅ Validate required environment variables (REPO_URL or GITHUB_TOKEN)
  - ✅ Validate REPO_URL format (HTTP/HTTPS/SSH)
  - ✅ Validate GITHUB_REPOSITORY format (owner/repo)
  - ✅ Validate SSH key paths and permissions
  - ✅ Validate interval, ports, and directory paths
  - ✅ Validate search pattern format
  - ✅ Helpful error messages with specific guidance
  - ✅ Early validation in main() with graceful exit

## 🔵 Low Priority (Future Enhancements)

### 11. Performance Optimizations
- **Issue**: Repository cloning on every run, no caching between runs
- **Impact**: Slower execution, unnecessary network usage
- **Solution**:
  - Implement intelligent caching for repository data
  - Add incremental updates for large repositories

### 12. Advanced Git Operations
- **Issue**: Basic Git operations, no advanced features
- **Impact**: Limited flexibility for complex workflows
- **Solution**:
  - Support for multiple remotes
  - Advanced branch management strategies
  - Git LFS support for large manifests

### 13. Multi-Repository Support
- **Issue**: Single repository scanning only
- **Impact**: Cannot monitor HelmReleases across multiple repositories
- **Solution**: Add support for multiple repository configurations

### 14. Webhook Integration
- **Issue**: No webhook support for external triggers
- **Impact**: Cannot integrate with external CI/CD systems
- **Solution**: Add webhook endpoint for external triggers

### 15. Database Backend
- **Issue**: No persistence, state stored in memory only
- **Impact**: Loss of state on restarts, no history tracking
- **Solution**: Add optional database backend for state persistence

## 📋 Implementation Phases

### Phase 1: Critical Fixes (Week 1-2)
1. ✅ Create missing `.gitignore` and `.dockerignore` files
2. ✅ Fix image registry inconsistencies
3. ✅ Replace hardcoded GitHub SSH key with dynamic fetching
4. ✅ Add basic health checks (completed)

### Phase 2: Security and Reliability (Week 3-4)
1. ✅ Implement namespace-scoped RBAC option (already implemented)
2. ✅ Add configuration validation
3. ✅ Single replica design decision documented
4. ✅ Add resource limits and requests (already implemented)

### Phase 3: Observability and Testing (Week 5-6)
1. ✅ Add Prometheus metrics and structured logging
2. ✅ Implement comprehensive unit tests
3. ✅ Add integration tests for Kubernetes operations
4. ❌ Set up GitHub Actions CI/CD pipeline

### Phase 4: Feature Enhancements (Week 7-8)
1. ❌ Implement OCI registry support
2. Add performance optimizations with caching
3. Enhance Git operations with advanced features
4. Add multi-repository support

### Phase 5: Advanced Features (Week 9-10)
1. Implement webhook integration
2. Add database backend option
3. Enhance monitoring and alerting
4. Add comprehensive documentation updates

## 📊 Success Metrics

- **Security**: Reduce CVSS score by addressing hardcoded secrets and over-privileged access
- **Reliability**: Achieve 99.9% uptime with proper health checks and multi-replica setup
- **Observability**: 100% of operations instrumented with metrics and structured logging
- **Testing**: 80% code coverage with comprehensive test suite
- **Performance**: 50% reduction in execution time through caching optimizations

## 🤝 Contributing

This roadmap is a living document. Contributions are welcome for any phase. Please:

1. Open issues for proposed enhancements
2. Create pull requests with clear descriptions
3. Update this roadmap when implementing features
4. Add tests for new functionality

## 📅 Timeline

- **Q4 2024**: Complete Phase 1 and 2
- **Q1 2025**: Complete Phase 3 and 4
- **Q2 2025**: Complete Phase 5 and roadmap review

---

*Last updated: October 2025*
