<!-- source: https://github.com/falcosecurity/falco-website/blob/c2cf6a9ef7d1ee48cc4189cc47f5e432a01628eb/content/en/docs/reference/rules/examples/access_camera.md -->
```yaml
- rule: access_camera
  desc: a process other than skype/webex tries to access the camera
  condition: evt.type = open and fd.name = /dev/video0 and not proc.name in (skype, webex)
  output: Unexpected process opening camera video device | command=%proc.cmdline
  priority: WARNING
 ```