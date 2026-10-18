<!-- source: https://github.com/awsdocs/aws-cloudtrail-user-guide/blob/56f54d99dfee0c3faf3d4a2b87bb572ad9edf58a/doc_source/cloudtrail-trail-naming-requirements.md -->
# CloudTrail naming requirements<a name="cloudtrail-trail-naming-requirements"></a>

CloudTrail resource names must meet the following requirements:
+ Contain only ASCII letters \(a\-z, A\-Z\), numbers \(0\-9\), periods \(\.\), underscores \(\_\), or dashes \(\-\)\.
+ Start with a letter or number, and end with a letter or number\.
+ Be between 3 and 128 characters\.
+ Have no adjacent periods, underscores or dashes\. Names like my\-\_namespace and my\-\\\-namespace are invalid\.
+ Not be in IP address format \(for example, `192.168.5.4`\)\.