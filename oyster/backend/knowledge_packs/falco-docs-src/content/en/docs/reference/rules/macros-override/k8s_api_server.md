<!-- source: https://github.com/falcosecurity/falco-website/blob/c2cf6a9ef7d1ee48cc4189cc47f5e432a01628eb/content/en/docs/reference/rules/macros-override/k8s_api_server.md -->
```yaml
- macro: k8s_api_server
  condition: (fd.sip="1.2.3.4" and fd.sport=8080)
```