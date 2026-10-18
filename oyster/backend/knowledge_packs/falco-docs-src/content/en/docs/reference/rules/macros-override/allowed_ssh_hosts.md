<!-- source: https://github.com/falcosecurity/falco-website/blob/c2cf6a9ef7d1ee48cc4189cc47f5e432a01628eb/content/en/docs/reference/rules/macros-override/allowed_ssh_hosts.md -->
```yaml
- macro: allowed_ssh_hosts
  condition: ssh_port
```