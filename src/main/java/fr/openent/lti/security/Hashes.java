package fr.openent.lti.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public final class Hashes {

	private static final SecureRandom RANDOM = new SecureRandom();
	private static final char[] HEX = "0123456789abcdef".toCharArray();

	private Hashes() {
	}

	/** Identifiant LTI pseudonyme : HMAC-SHA256(sel propre à l'outil, identifiant ENT). */
	public static String pseudonym(String salt, String userId) {
		try {
			final Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(new SecretKeySpec(salt.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
			return hex(mac.doFinal(userId.getBytes(StandardCharsets.UTF_8)));
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	public static String randomHex(int bytes) {
		final byte[] b = new byte[bytes];
		RANDOM.nextBytes(b);
		return hex(b);
	}

	private static String hex(byte[] bytes) {
		final char[] out = new char[bytes.length * 2];
		for (int i = 0; i < bytes.length; i++) {
			out[i * 2] = HEX[(bytes[i] >> 4) & 0xF];
			out[i * 2 + 1] = HEX[bytes[i] & 0xF];
		}
		return new String(out);
	}
}
