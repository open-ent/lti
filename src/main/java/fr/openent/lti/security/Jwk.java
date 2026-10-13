package fr.openent.lti.security;

import fr.openent.lti.core.LtiException;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

/** Conversion clé publique RSA ↔ JWK (RFC 7517) et sélection d'une clé dans un JWKS. */
public final class Jwk {

	private Jwk() {
	}

	public static JsonObject toJwk(RSAPublicKey key, String kid) {
		return new JsonObject()
				.put("kty", "RSA")
				.put("alg", Jwt.RS256)
				.put("use", "sig")
				.put("kid", kid)
				.put("n", unsigned(key.getModulus()))
				.put("e", unsigned(key.getPublicExponent()));
	}

	public static RSAPublicKey toPublicKey(JsonObject jwk) throws LtiException {
		if (jwk == null || !"RSA".equals(jwk.getString("kty"))) {
			throw new LtiException(401, "unsupported.jwk");
		}
		try {
			final BigInteger n = new BigInteger(1, Base64.getUrlDecoder().decode(jwk.getString("n")));
			final BigInteger e = new BigInteger(1, Base64.getUrlDecoder().decode(jwk.getString("e")));
			return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
		} catch (Exception ex) {
			throw new LtiException(401, "invalid.jwk");
		}
	}

	/**
	 * Sélectionne la clé de signature d'un JWKS : par kid si fourni, sinon la seule clé RSA présente.
	 */
	public static JsonObject select(JsonObject jwks, String kid) throws LtiException {
		final JsonArray keys = jwks == null ? null : jwks.getJsonArray("keys");
		if (keys == null || keys.isEmpty()) {
			throw new LtiException(401, "empty.jwks");
		}
		JsonObject candidate = null;
		int rsaKeys = 0;
		for (Object o : keys) {
			if (!(o instanceof JsonObject)) {
				continue;
			}
			final JsonObject key = (JsonObject) o;
			if (!"RSA".equals(key.getString("kty")) || "enc".equals(key.getString("use"))) {
				continue;
			}
			rsaKeys++;
			if (kid != null && kid.equals(key.getString("kid"))) {
				return key;
			}
			candidate = key;
		}
		if (kid == null && rsaKeys == 1) {
			return candidate;
		}
		throw new LtiException(401, "unknown.jwk.kid");
	}

	private static String unsigned(BigInteger value) {
		byte[] bytes = value.toByteArray();
		if (bytes.length > 1 && bytes[0] == 0) {
			final byte[] trimmed = new byte[bytes.length - 1];
			System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
			bytes = trimmed;
		}
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}
}
