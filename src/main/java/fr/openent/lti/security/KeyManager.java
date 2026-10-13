package fr.openent.lti.security;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.UUID;

/**
 * Clés de signature de la plateforme. La clé privée (PEM PKCS#8) vient de la configuration
 * (lti.private-key), elle-même alimentée par un Secret Kubernetes. Sans clé configurée,
 * une clé éphémère est générée : acceptable en développement seulement (elle change à
 * chaque redémarrage et diffère entre instances).
 */
public final class KeyManager {

	private static final Logger log = LoggerFactory.getLogger(KeyManager.class);

	private final PrivateKey privateKey;
	private final RSAPublicKey publicKey;
	private final String kid;
	private final JsonArray previousPublicKeys;

	public KeyManager(PrivateKey privateKey, RSAPublicKey publicKey, String kid, JsonArray previousPublicKeys) {
		this.privateKey = privateKey;
		this.publicKey = publicKey;
		this.kid = kid;
		this.previousPublicKeys = previousPublicKeys == null ? new JsonArray() : previousPublicKeys;
	}

	public static KeyManager fromConfig(JsonObject ltiConfig) {
		final String pem = ltiConfig.getString("private-key", "");
		final JsonArray previous = ltiConfig.getJsonArray("previous-public-keys", new JsonArray());
		if (pem.trim().isEmpty()) {
			log.warn("[LTI] No lti.private-key configured: generating an ephemeral RSA key (development only).");
			final KeyPair pair = generate();
			return new KeyManager(pair.getPrivate(), (RSAPublicKey) pair.getPublic(), UUID.randomUUID().toString(), previous);
		}
		final RSAPrivateCrtKey key = parsePkcs8(pem);
		return new KeyManager(key, publicFromPrivate(key), ltiConfig.getString("kid", "openent-lti-1"), previous);
	}

	public static KeyPair generate() {
		try {
			final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);
			return generator.generateKeyPair();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	static RSAPrivateCrtKey parsePkcs8(String pem) {
		final String body = pem
				.replace("\\n", "\n")
				.replaceAll("-----BEGIN [A-Z ]+-----", "")
				.replaceAll("-----END [A-Z ]+-----", "")
				.replaceAll("\\s", "");
		try {
			final byte[] der = Base64.getDecoder().decode(body);
			return (RSAPrivateCrtKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
		} catch (Exception e) {
			throw new IllegalArgumentException("lti.private-key must be an RSA private key in PKCS#8 PEM format", e);
		}
	}

	private static RSAPublicKey publicFromPrivate(RSAPrivateCrtKey key) {
		try {
			final BigInteger modulus = key.getModulus();
			return (RSAPublicKey) KeyFactory.getInstance("RSA")
					.generatePublic(new RSAPublicKeySpec(modulus, key.getPublicExponent()));
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	public String sign(JsonObject payload) {
		return Jwt.sign(payload, privateKey, kid);
	}

	public RSAPublicKey getPublicKey() {
		return publicKey;
	}

	public String getKid() {
		return kid;
	}

	/** JWKS public : clé courante + clés précédentes conservées pendant la rotation. */
	public JsonObject jwks() {
		final JsonArray keys = new JsonArray().add(Jwk.toJwk(publicKey, kid));
		for (Object o : previousPublicKeys) {
			if (o instanceof JsonObject) {
				keys.add(o);
			}
		}
		return new JsonObject().put("keys", keys);
	}
}
