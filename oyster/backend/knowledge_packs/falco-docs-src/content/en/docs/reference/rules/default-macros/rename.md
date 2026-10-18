<!-- source: https://github.com/falcosecurity/falco-website/blob/c2cf6a9ef7d1ee48cc4189cc47f5e432a01628eb/content/en/docs/reference/rules/default-macros/rename.md -->
```yaml
- macro: rename
  condition: evt.type in (rename, renameat)
```