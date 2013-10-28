ImportCert
==========

java Certificate Import Utility with proxy support

Modified ImportCert.java from SUN/Oracle to support being behind a proxy
Updated Argument handling
Not sure if httpProxy AND httpsProxy both need set.  currently only handling httpProxy

Compile:  javac ImportCert.java

Run:  java ImportCert url

Required arg:  url
Optional:

url:port (defaults to 443)

-pw password --- java keystore (cacerts) password, defaults to "changeit"

-httpProxy IP:port --- IP address and port of the proxy

example:  java importCert url:443 -pw changeit -httpProxy 192.168.1.4:8080 