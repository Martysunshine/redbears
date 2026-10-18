<!-- source: https://github.com/falcosecurity/falco-website/blob/c2cf6a9ef7d1ee48cc4189cc47f5e432a01628eb/content/en/docs/reference/rules/default-macros/open_read.md -->
```yaml
- macro: open_read
  condition: (evt.type=open or evt.type=openat) and evt.is_open_read=true and fd.typechar='f' and fd.num>=0
```