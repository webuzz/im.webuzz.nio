package im.webuzz.nio;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class NioHostnameVerifier {

	private String orgHost;

	static Set<String> allKnownCAs = Collections.newSetFromMap(new ConcurrentHashMap<String, Boolean>());
	static Set<String> allKnownCANames = Collections.newSetFromMap(new ConcurrentHashMap<String, Boolean>());

	static {
		allKnownCANames.addAll(Arrays.asList(NioConfig.sslKnownCANames));
		allKnownCAs.addAll(Arrays.asList(NioConfig.sslKnownCADigests));
	}

	public NioHostnameVerifier(String orgHost) {
		if (orgHost != null) {
			int colonIndex = orgHost.indexOf(':');
			if (colonIndex != -1) {
				orgHost = orgHost.substring(0, colonIndex);
			}
			this.orgHost = orgHost;
		}
	}

	static String getThumbPrint(java.security.cert.X509Certificate cert)
			throws NoSuchAlgorithmException, java.security.cert.CertificateEncodingException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] der = cert.getEncoded();
		md.update(der);
		byte[] digest = md.digest();
		return hexify(digest);
	}

	static String hexify(byte bytes[]) {
		char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7',
				'8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
		StringBuffer buf = new StringBuffer(bytes.length * 2);
		for (int i = 0; i < bytes.length; ++i) {
			buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
			buf.append(hexDigits[bytes[i] & 0x0f]);
		}
		return buf.toString();
	}

	static String getCNName(Principal x500s) {
		String x500Domain = "";
		//CN=AddTrust External CA Root
		String[] x500DomainDNArray = x500s.getName().split(",");
		for (String tmpDN : x500DomainDNArray) {
			if (tmpDN.startsWith("CN=")) {
				x500Domain = tmpDN.split("=")[1];
				break;
			}
		}
		return x500Domain;
	}

	static int bytesIndexOf(byte[] bytes, byte b, int fromIndex) {
		int i = fromIndex;
		int max = bytes.length;
		for (; i < max; i++) {
			if (bytes[i] == b) {
				return i;
			}
		}
		return -1;
	}

	static int indexOf(byte[] source, int sourceOffset, int sourceCount, byte[] target, int targetOffset, int targetCount, int fromIndex) {
		if (fromIndex >= sourceCount) {
			return (targetCount == 0 ? sourceCount : -1);
		}
		if (fromIndex < 0) {
			fromIndex = 0;
		}
		if (targetCount == 0) {
			return fromIndex;
		}

		byte first = target[targetOffset];
		int max = sourceOffset + (sourceCount - targetCount);

		for (int i = sourceOffset + fromIndex; i <= max; i++) {
			/* Look for first character. */
			if (source[i] != first) {
				while (++i <= max && source[i] != first)
					;
			}

			/* Found first character, now look at the rest of v2 */
			if (i <= max) {
				int j = i + 1;
				int end = j + targetCount - 1;
				for (int k = targetOffset + 1; j < end && source[j] == target[k]; j++, k++)
					;

				if (j == end) {
					/* Found whole string. */
					return i - sourceOffset;
				}
			}
		}
		return -1;
	}

	/*
	 00000410: 6f63 612e 636f 6d30 2706 0355 1d11 0420  oca.com0'..U...
	 00000420: 301e 820e 2a2e 3566 3337 3561 3836 2e63  0...*.5f375a86.c
	 00000430: 6f6d 820c 3566 3337 3561 3836 2e63 6f6d  om..5f375a86.com
	 00000440: 300d 0609 2a86 4886 f70d 0101 0b05 0003  0...*.H.........


	 00000360: 636f 6d30 8203 4006 0355 1d11 0482 0337  com0..@..U.....7
	 00000370: 3082 0333 821b 736e 6931 3832 3339 322e  0..3..sni182392.
	 00000380: 636c 6f75 6466 6c61 7265 7373 6c2e 636f  cloudflaressl.co
	 00000390: 6d82 0d2a 2e61 6f65 6772 696e 642e 7275  m..*.aoegrind.ru
	// */
	static String[] parseAlternativeSN(byte[] bytes) {
		byte[] key = new byte[]{0x55, 0x1d, 0x11, 0x04};
		int idx = indexOf(bytes, 0, bytes.length, key, 0, key.length, 0);
		if (idx == -1) {
			return null;
		}
		int length = 0;
		int index = idx + 4;
		byte next = bytes[index];
		if (next == (byte) 0x82) {
			index++;
			int next1 = bytes[index] & 0xff;
			index++;
			int next2 = bytes[index] & 0xff;
			length = 0x0100 * next1 + next2;
		} else if (next == (byte) 0x81) {
			index++;
			length = bytes[index] & 0xff;
		} else {
			length = next;
		}
		index++;
		// next is 0x30
		index++;
		next = bytes[index];
		if (next == (byte) 0x82) {
			index++;
			int next1 = bytes[index] & 0xff;
			index++;
			int next2 = bytes[index] & 0xff;
			length = 0x0100 * next1 + next2;
		} else if (next == (byte) 0x81) {
			index++;
			length = bytes[index] & 0xff;
		} else {
			length = next;
		}
		index++;
		List<String> names = new ArrayList<String>();
		idx = index;
		while (idx < index + length) {
			idx = bytesIndexOf(bytes, (byte) 0x82, idx);
			if (idx == -1) {
				break;
			}
			idx++;
			next = bytes[idx];
			int itemLength = 0;
			if (next == (byte) 0x82) {
				idx++;
				int next1 = bytes[idx] & 0xff;
				idx++;
				int next2 = bytes[idx] & 0xff;
				itemLength = 0x0100 * next1 + next2;
			} else {
				itemLength = next;
			}
			idx++;
			names.add(new String(bytes, idx, itemLength));
			idx += itemLength;
		}
		if (names.size() == 0) {
			return null;
		}
		return names.toArray(new String[names.size()]);
	}

	public boolean verify(String hostname, java.security.cert.X509Certificate[] peerCerts) {
		boolean bKnownCA = false;
		for (int i = peerCerts.length - 1; i >= 0; i--) {
			java.security.cert.X509Certificate peerCert = peerCerts[i];
			try {
				String thumb = getThumbPrint(peerCert);
				if (allKnownCAs.contains(thumb)) {
					bKnownCA = true;
					break;
				}
				if (allKnownCANames.contains(getCNName(peerCert.getIssuerDN()))
						|| allKnownCANames.contains(getCNName(peerCert.getSubjectDN()))) {
					try {
						peerCert.checkValidity();
						bKnownCA = true;
						break;
					} catch (Exception e) {
						e.printStackTrace();
						return false;
					}
				}
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
				return false;
			} catch (java.security.cert.CertificateEncodingException e) {
				e.printStackTrace();
				return false;
			}
		}
		if (!bKnownCA) {
			new RuntimeException("Unknown Root CA certiicate, may be a MITM attack! " + hostname + " : " + orgHost).printStackTrace();;
			return false;
		}
		for (java.security.cert.X509Certificate peerCert : peerCerts) {
			String subjectDomain = getCNName(peerCert.getSubjectDN());
			if (subjectDomain == null ||subjectDomain.length() == 0) {
				continue;
			}
			boolean matched = false;
			if (subjectDomain.equalsIgnoreCase(hostname) || subjectDomain.equalsIgnoreCase(orgHost)) {
				matched = true;
			} else if (subjectDomain.contains("*")) {
				String regexDomain = subjectDomain.toLowerCase().replaceAll("\\.", "\\\\.").replaceAll("\\*", "\\[^\\.\\]*");
				if ((hostname != null && hostname.toLowerCase().matches(regexDomain)) ||
						(orgHost != null && orgHost.toLowerCase().matches(regexDomain))) {
					matched = true;
				}
			}
			if (!matched) {
				String[] domains = null;
				try {
					domains = parseAlternativeSN(peerCert.getEncoded());
				} catch (Exception e) {
				}
				if (domains != null) {
					for (String domain : domains) {
						if (domain.equalsIgnoreCase(hostname) || domain.equalsIgnoreCase(orgHost)) {
							matched = true;
							break;
						} else if (domain.contains("*")) {
							String regexDomain = domain.toLowerCase().replaceAll("\\.", "\\\\.").replaceAll("\\*", "\\[^\\.\\]*");
							if ((hostname != null && hostname.toLowerCase().matches(regexDomain)) ||
									(orgHost != null && orgHost.toLowerCase().matches(regexDomain))) {
								matched = true;
								break;
							}
						}
					}
				}
			}
			/*
			if (!matched) {
				String str = peerCert.toString();
				String altKey = "Subject Alternative Name:";
				int idx = str.indexOf(altKey);
				if (idx != -1) {
					int startIdx = str.indexOf("DNS:", idx + altKey.length());
					if (startIdx != -1) {
						int endIdx = str.indexOf('\n', startIdx + 4);
						if (endIdx != -1) {
							String[] domains = str.substring(startIdx + 4, endIdx).split(", ");
							for (String domain : domains) {
								if (domain.equalsIgnoreCase(hostname) || domain.equalsIgnoreCase(orgHost)) {
									matched = true;
									break;
								} else if (domain.contains("*")) {
									String regexDomain = domain.toLowerCase().replaceAll("\\.", "\\\\.").replaceAll("\\*", "\\[^\\.\\]*");
									if ((hostname != null && hostname.toLowerCase().matches(regexDomain)) ||
											(orgHost != null && orgHost.toLowerCase().matches(regexDomain))) {
										matched = true;
										break;
									}
								}
							}
						}
					}
				}
			}
			// */
			try {
				peerCert.checkValidity();
				if (matched) {
					// For matched host names check certificate's validity
					return true;
				}
			} catch (Exception e) {
				e.printStackTrace();
				return false;
			}
		}
		return false;
	}

}
