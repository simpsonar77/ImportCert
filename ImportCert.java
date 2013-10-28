/*
 * Copyright 2006 Sun Microsystems, Inc.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Sun Microsystems nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Modified by Andrew Simpson - USN - NSWC Crane
 * Change:  Adds in proxy support
 * Change:  modify argument handler
 */

import java.io.*;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.text.ParseException;

import javax.net.ssl.*;

public class ImportCert {

  public static void main(String[] args) throws Exception {
	String host;
	String defaultPW = "changeit"; //Default passphrase for cacerts
	String newPW = "";
	String httpProxyIP ="";
	int httpProxyPort = 0;
	String httpsProxyIP ="";
	int httpsProxyPort= 0;
	boolean setPW = false;
	boolean useProxy = false;
	int port;
	char[] passphrase;
	try {
		if (args.length > 0 ) {
		} else {
	    System.err.println("Usage: java InstallCert <host>[:port] [-pw passphrase] [-httpProxy IP:Port] [-httpsProxy IP:Port]");
	    return;
		}
		//Parse host/port first
	    String[] c = args[0].split(":");
	    host = c[0];
	    port = (c.length == 1) ? 443 : Integer.parseInt(c[1]);
	    
		for (int i=1;i<args.length;i++)
		{
			if (args[i].equals("-pw"))
			{
				setPW=true;
				newPW = args[i+1];
			}
			else if (args[i].equals("-httpProxy"))
			{
				//-httpProxy ipaddr:port
				useProxy=true;
				String[] httpProxy = args[i+1].split(":");
				httpProxyIP=httpProxy[0];
				httpProxyPort=Integer.parseInt(httpProxy[1]);
			}
			else if (args[i].equals("httpsProxy"))
			{
				//-httpsProxy ipaddr:port
				useProxy=true;
				String[] httpsProxy = args[i+1].split(":");
				httpsProxyIP=httpsProxy[0];
				httpsProxyPort=Integer.parseInt(httpsProxy[1]);
			}
		}
	
		if (setPW)
		{
		    passphrase = newPW.toCharArray();
		}
		else
			passphrase = defaultPW.toCharArray();  
		
	} catch (Exception e) {
		 System.err.println("Usage: java InstallCert <host>[:port] [passphrase]");
		 return;
	}
	
	char SEP = File.separatorChar;
	File securityDir = new File(System.getProperty("java.home") + SEP + "lib" + SEP + "security");
	File certFile = new File(securityDir, "cacerts");
	if (!certFile.exists()) {
		System.err.println("KeyStore " + certFile + " does not exist");
		return;
	}
	
	System.out.println("Loading KeyStore " + certFile + "...");
	InputStream in = new FileInputStream(certFile);
	KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
	ks.load(in, passphrase);
	in.close();

	SSLContext context = SSLContext.getInstance("TLS");
	TrustManagerFactory tmf =  TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
	tmf.init(ks);
	X509TrustManager defaultTrustManager = (X509TrustManager)tmf.getTrustManagers()[0];
	SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
	context.init(null, new TrustManager[] {tm}, null);
	SSLSocketFactory factory = context.getSocketFactory();

	//if proxy not specified, create old way, otherwise, do this
	SSLSocket socket;
	if (useProxy)
	{
	  InetSocketAddress proxyAddr = new InetSocketAddress(httpProxyIP, httpProxyPort);
	  Socket underlying = new Socket(new Proxy(Proxy.Type.SOCKS,proxyAddr)); 
	  underlying.connect(new InetSocketAddress(host, port));
	  System.out.println("Opening connection to " + host + ":" + port + "... with Proxy = " + httpProxyIP + ":" + httpProxyPort);
	  socket = (SSLSocket) factory.createSocket(
            underlying,
            httpProxyIP,
            httpProxyPort,
            true);
	} else
	{
		 socket = (SSLSocket)factory.createSocket(host, port);
	}
		  
	
	socket.setSoTimeout(10000);
	try {
	    System.out.println("Starting SSL handshake...");
	    socket.startHandshake();
	    socket.close();
	    System.out.println();
	    System.out.println("No errors, certificate is already trusted");
	} catch (SSLException e) {
	    e.printStackTrace();
	}

	X509Certificate[] chain = tm.chain;
	if (chain == null) {
	    System.out.println("Could not obtain server certificate chain");
	    return;
	}

	BufferedReader reader =	new BufferedReader(new InputStreamReader(System.in));

	System.out.println();
	System.out.println("Server sent " + chain.length + " certificate(s):");
	System.out.println();
	MessageDigest sha1 = MessageDigest.getInstance("SHA1");
	MessageDigest md5 = MessageDigest.getInstance("MD5");
	for (int i = 0; i < chain.length; i++) {
	    X509Certificate cert = chain[i];
	    System.out.println(" " + (i + 1) + " Subject " + cert.getSubjectDN());
	    System.out.println("   Issuer  " + cert.getIssuerDN());
	    sha1.update(cert.getEncoded());
	    System.out.println("   sha1    " + toHexString(sha1.digest()));
	    md5.update(cert.getEncoded());
	    System.out.println("   md5     " + toHexString(md5.digest()));
	    System.out.println();
	}

	System.out.println("Enter certificate to add to trusted keystore or 'q' to quit: [1]");
	String line = reader.readLine().trim();
	int k;
	try {
	    k = (line.length() == 0) ? 0 : Integer.parseInt(line) - 1;
	} catch (NumberFormatException e) {
	    System.out.println("KeyStore not changed");
	    return;
	}
	
	System.out.println("Enter alias to add this certificate as");
	String alias = reader.readLine().trim();
	if (alias.length() == 0) {
		System.err.println("Alias must not be empty");
		return;
	}

	X509Certificate cert = chain[k];
	ks.setCertificateEntry(alias, cert);
	
	if (!certFile.canWrite()) {
		System.err.println("KeyStore is not writeable");
	}

	OutputStream out = new FileOutputStream(certFile);
	ks.store(out, passphrase);
	out.close();

	System.out.println();
	System.out.println(cert);
	System.out.println();
	System.out.println("Added certificate to KeyStore using alias '" + alias + "'");
    }

	private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();

	private static String toHexString(byte[] bytes) {
		StringBuilder sb = new StringBuilder(bytes.length * 3);
		for (int b : bytes) {
			b &= 0xff;
			sb.append(HEXDIGITS[b >> 4]);
			sb.append(HEXDIGITS[b & 15]);
			sb.append(' ');
		}
		return sb.toString();
	}

	private static class SavingTrustManager implements X509TrustManager {

		private final X509TrustManager tm;
		private X509Certificate[] chain;

		SavingTrustManager(X509TrustManager tm) {
			this.tm = tm;
		}

		public X509Certificate[] getAcceptedIssuers() {
			throw new UnsupportedOperationException();
		}

		public void checkClientTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
			throw new UnsupportedOperationException();
		}

		public void checkServerTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
			this.chain = chain;
			tm.checkServerTrusted(chain, authType);
		}
	}
}