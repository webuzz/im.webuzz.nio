package im.webuzz.nio;

public class NioConfig {
	
	public static String[] sslProtocols = new String[] {
		"TLSv1.2",
		"TLSv1.1",
		"TLSv1"
	};
	// From Java 1.8
	// grep -v SSL_ ~/ciphers18.txt | grep -v "_DH_" | grep -v "_RC4_" | grep -v "_NULL_" | grep -v "_anon_" | grep -v "_EMPTY_" | grep -v "_KRB5_" | grep -v "_DSS_" | awk '{printf "\"%s\",\r\n", $1}'
	public static String[] sslCipherSuites = new String[] {
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
		"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
	};
	public static boolean sslSessionCreation = true;

}
