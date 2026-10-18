<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/ftp/send/send-file-using-ftp.yml -->
rule:
  meta:
    name: send file using FTP
    namespace: communication/ftp/send
    authors:
      - michael.hunhoff@mandiant.com
      - anushka.virgaonkar@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Communication::FTP Communication::Send File [C0004.001]
      - Communication::FTP Communication::WinINet [C0004.002]
    examples:
      - Practical Malware Analysis Lab 20-02.exe_:0x401380
  features:
    - or:
      - and:
        - api: wininet.FtpPutFile
        - optional:
          - or:
            - api: wininet.FtpSetCurrentDirectory
            - and:
              - api: wininet.InternetConnect
              - number: 0x15 = IPPORT_FTP
      - and:
        - api: System.Net.WebRequest::Create
        - string: "STOR"
        - property/write: System.Net.WebRequest::Method
