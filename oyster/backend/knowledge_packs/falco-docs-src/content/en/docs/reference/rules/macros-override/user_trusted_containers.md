<!-- source: https://github.com/falcosecurity/falco-website/blob/c2cf6a9ef7d1ee48cc4189cc47f5e432a01628eb/content/en/docs/reference/rules/macros-override/user_trusted_containers.md -->
```yaml
- macro: user_trusted_containers
  condition: (container.image startswith sysdig/agent)
```