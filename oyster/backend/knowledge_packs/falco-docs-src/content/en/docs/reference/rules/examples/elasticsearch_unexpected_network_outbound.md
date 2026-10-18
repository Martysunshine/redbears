<!-- source: https://github.com/falcosecurity/falco-website/blob/c2cf6a9ef7d1ee48cc4189cc47f5e432a01628eb/content/en/docs/reference/rules/examples/elasticsearch_unexpected_network_outbound.md -->
```yaml
- macro: outbound
  condition: syscall.type=connect and (fd.typechar=4 or fd.typechar=6)

- macro: elasticsearch_cluster_port
  condition: fd.sport=9300

- rule: elasticsearch_unexpected_network_outbound
  desc: outbound network traffic from elasticsearch on a port other than the standard ports
  condition: user.name = elasticsearch and outbound and not elasticsearch_cluster_port
  output: "Outbound network traffic from Elasticsearch on unexpected port | connection=%fd.name"
  priority: WARNING
```
