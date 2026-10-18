<!-- source: https://github.com/falcosecurity/falco-website/blob/c2cf6a9ef7d1ee48cc4189cc47f5e432a01628eb/content/en/docs/reference/rules/macros-override/k8s_containers.md -->
```yaml
- macro: k8s_containers
  condition: >
    (container.image startswith gcr.io/google_containers/hyperkube-amd64 or
    container.image startswith gcr.io/google_containers/kube2sky or
    container.image startswith sysdig/agent or
    container.image startswith sysdig/falco or
    container.image startswith sysdig/sysdig)
```