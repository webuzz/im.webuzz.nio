package im.webuzz.nio;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.StringTokenizer;

import javax.net.ssl.SSLException;

public class VerifyUtils {

	/**
	 * This contains a list of 2nd-level domains that aren't allowed to have
	 * wildcards when combined with country-codes. For example: [*.co.uk].
	 * <p/>
	 * The [*.co.uk] problem is an interesting one. Should we just hope that
	 * CA's would never foolishly allow such a certificate to happen? Looks like
	 * we're the only implementation guarding against this. Firefox, Curl, Sun
	 * Java 1.4, 5, 6 don't bother with this check.
	 */
	private final static String[] BAD_COUNTRY_2LDS = { "ac", "co", "com", "ed", "edu", "go", "gouv", "gov", "info",
			"lg", "ne", "net", "or", "org" };

	static {
		// Just in case developer forgot to manually sort the array. :-)
		Arrays.sort(BAD_COUNTRY_2LDS);
	}

	public static final void verify(String host, X509Certificate cert) throws SSLException {
		String[] cns = getCNs(cert);
		String[] subjectAlts = getSubjectAlts(cert, host);
		verify(host, cns, subjectAlts, true);
	}

	public static final void verify(String host, final String[] cns, final String[] subjectAlts,
			final boolean strictWithSubDomains) throws SSLException {
		if (host != null) {
			int idx = host.lastIndexOf(':');
			if (idx != -1) {
				host = host.substring(0, idx);
			}
		}
		// Build the list of names we're going to check. Our DEFAULT and
		// STRICT implementations of the HostnameVerifier only use the
		// first CN provided. All other CNs are ignored.
		// (Firefox, wget, curl, Sun Java 1.4, 5, 6 all work this way).
		LinkedList<String> names = new LinkedList<String>();
		if (cns != null && cns.length > 0 && cns[0] != null) {
			names.add(cns[0]);
		}
		if (subjectAlts != null) {
			for (String subjectAlt : subjectAlts) {
				if (subjectAlt != null) {
					names.add(subjectAlt);
				}
			}
		}

		if (names.isEmpty()) {
			String msg = "Certificate for <" + host + "> doesn't contain CN or DNS subjectAlt";
			throw new SSLException(msg);
		}

		// StringBuilder for building the error message.
		StringBuilder buf = new StringBuilder();

		// We're can be case-insensitive when comparing the host we used to
		// establish the socket to the hostname in the certificate.
		String hostName = host.trim().toLowerCase(Locale.ENGLISH);
		boolean match = false;
		for (Iterator<String> it = names.iterator(); it.hasNext();) {
			// Don't trim the CN, though!
			String cn = it.next();
			cn = cn.toLowerCase(Locale.ENGLISH);
			// Store CN in StringBuilder in case we need to report an error.
			buf.append(" <");
			buf.append(cn);
			buf.append('>');
			if (it.hasNext()) {
				buf.append(" OR");
			}

			// The CN better have at least two dots if it wants wildcard
			// action. It also can't be [*.co.uk] or [*.co.jp] or
			// [*.org.uk], etc...
			String parts[] = cn.split("\\.");
			boolean doWildcard = parts.length >= 3 && parts[0].endsWith("*") && acceptableCountryWildcard(cn)
					&& !isIPAddress(host);

			if (doWildcard) {
				if (parts[0].length() > 1) { // e.g. server*
					String prefix = parts[0].substring(0, parts.length - 2); // e.g. server
					String suffix = cn.substring(parts[0].length()); // skip wildcard part from cn
					String hostSuffix = hostName.substring(prefix.length()); // skip wildcard part from host
					match = hostName.startsWith(prefix) && hostSuffix.endsWith(suffix);
				} else {
					match = hostName.endsWith(cn.substring(1));
				}
				if (match && strictWithSubDomains) {
					// If we're in strict mode, then [*.foo.com] is not
					// allowed to match [a.b.foo.com]
					match = countDots(hostName) == countDots(cn);
				}
			} else {
				match = hostName.equals(cn);
			}
			if (match) {
				break;
			}
		}
		if (!match) {
			throw new SSLException("hostname in certificate didn't match: <" + host + "> !=" + buf);
		}
	}

	public static boolean acceptableCountryWildcard(String cn) {
		String parts[] = cn.split("\\.");
		if (parts.length != 3 || parts[2].length() != 2) {
			return true; // it's not an attempt to wildcard a 2TLD within a country code
		}
		return Arrays.binarySearch(BAD_COUNTRY_2LDS, parts[1]) < 0;
	}

	public static String[] getCNs(X509Certificate cert) {
		LinkedList<String> cnList = new LinkedList<String>();
		/*
		 * Sebastian Hauer's original StrictSSLProtocolSocketFactory used
		 * getName() and had the following comment:
		 * 
		 * Parses a X.500 distinguished name for the value of the "Common Name"
		 * field. This is done a bit sloppy right now and should probably be
		 * done a bit more according to <code>RFC 2253</code>.
		 * 
		 * I've noticed that toString() seems to do a better job than getName()
		 * on these X500Principal objects, so I'm hoping that addresses
		 * Sebastian's concern.
		 * 
		 * For example, getName() gives me this:
		 * 1.2.840.113549.1.9.1=#16166a756c6975736461766965734063756362632e636f6d
		 * 
		 * whereas toString() gives me this: EMAILADDRESS=juliusdavies@cucbc.com
		 * 
		 * Looks like toString() even works with non-ascii domain names! I
		 * tested it with "花子.co.jp" and it worked fine.
		 */
		String subjectPrincipal = cert.getSubjectX500Principal().toString();
		StringTokenizer st = new StringTokenizer(subjectPrincipal, ",");
		while (st.hasMoreTokens()) {
			String tok = st.nextToken();
			int x = tok.indexOf("CN=");
			if (x >= 0) {
				cnList.add(tok.substring(x + 3));
			}
		}
		if (!cnList.isEmpty()) {
			String[] cns = new String[cnList.size()];
			cnList.toArray(cns);
			return cns;
		} else {
			return null;
		}
	}

	/**
	 * Extracts the array of SubjectAlt DNS or IP names from an X509Certificate.
	 * Returns null if there aren't any.
	 * 
	 * @param cert
	 *            X509Certificate
	 * @param hostname
	 * @return Array of SubjectALT DNS or IP names stored in the certificate.
	 */
	private static String[] getSubjectAlts(final X509Certificate cert, final String hostname) {
		int subjectType;
		if (isIPAddress(hostname)) {
			subjectType = 7;
		} else {
			subjectType = 2;
		}

		LinkedList<String> subjectAltList = new LinkedList<String>();
		Collection<List<?>> c = null;
		try {
			c = cert.getSubjectAlternativeNames();
		} catch (CertificateParsingException cpe) {
			cpe.printStackTrace();
		}
		if (c != null) {
			for (List<?> aC : c) {
				List<?> list = aC;
				int type = ((Integer) list.get(0)).intValue();
				if (type == subjectType) {
					String s = (String) list.get(1);
					subjectAltList.add(s);
				}
			}
		}
		if (!subjectAltList.isEmpty()) {
			String[] subjectAlts = new String[subjectAltList.size()];
			subjectAltList.toArray(subjectAlts);
			return subjectAlts;
		} else {
			return null;
		}
	}

	/**
	 * Extracts the array of SubjectAlt DNS names from an X509Certificate.
	 * Returns null if there aren't any.
	 * <p/>
	 * Note: Java doesn't appear able to extract international characters from
	 * the SubjectAlts. It can only extract international characters from the CN
	 * field.
	 * <p/>
	 * (Or maybe the version of OpenSSL I'm using to test isn't storing the
	 * international characters correctly in the SubjectAlts?).
	 * 
	 * @param cert
	 *            X509Certificate
	 * @return Array of SubjectALT DNS names stored in the certificate.
	 */
	public static String[] getDNSSubjectAlts(X509Certificate cert) {
		return getSubjectAlts(cert, null);
	}

	/**
	 * Counts the number of dots "." in a string.
	 * 
	 * @param s
	 *            string to count dots from
	 * @return number of dots
	 */
	public static int countDots(final String s) {
		int count = 0;
		for (int i = 0; i < s.length(); i++) {
			if (s.charAt(i) == '.') {
				count++;
			}
		}
		return count;
	}

	private static boolean isIPAddress(final String hostname) {
		return hostname != null
				&& (isValidIPv4Address(hostname) || isValidIPv4Address(hostname));
	}

	public static boolean isValidIPv4Address(String ip) {
    	int count = 0;
		int cursor = 0;
		do {
			int idx = ip.indexOf('.', cursor);
			try {
				int ipSeg = Integer.parseInt(ip.substring(cursor, idx < 0 ? ip.length() : idx));
				if (ipSeg < 0 || ipSeg > 255) {
					return false;
				}
			} catch (NumberFormatException e) {
				return false;
			}
			count++;
			if (idx == -1) {
				return count == 4;
			}
			cursor = idx + 1;
		} while (true);
    }

}
