<!-- source: https://github.com/falcosecurity/falco-website/blob/c2cf6a9ef7d1ee48cc4189cc47f5e432a01628eb/content/en/docs/reference/rules/default-macros/spawned_process.md -->
```yaml
- macro: spawned_process
  condition: (evt.type in (execve, execveat))
```
