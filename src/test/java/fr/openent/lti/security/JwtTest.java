package fr.openent.lti.security;

import fr.openent.lti.core.LtiException;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static org.junit.Assert.*;

public class JwtTest {

	private static final KeyPair KEYS = KeyManager.generate();
	private static final KeyPair OTHER = KeyManager.generate();

	@Test
	public void signsAndVerifiesRs256() throws Exception {
		final String token = Jwt.sign(new JsonObject().put("sub", "u1").put("exp", 2000), KEYS.getPrivate(), "k1");
		final Jwt.Decoded decoded = Jwt.decode(token);
		assertEquals("k1", decoded.kid());
		assertEquals("RS256", decoded.header.getString("alg"));
		Jwt.verify(decoded, KEYS.getPublic());
		Jwt.checkTimes(decoded.payload, 1000, 60);
		assertEquals("u1", decoded.payload.getString("sub"));
	}

	@Test(expected = LtiException.class)
	public void rejectsSignatureFromAnotherKey() throws Exception {
		final String token = Jwt.sign(new JsonObject().put("sub", "u1"), OTHER.getPrivate(), "k1");
		Jwt.verify(Jwt.decode(token), KEYS.getPublic());
	}

	@Test(expected = LtiException.class)
	public void rejectsTamperedPayload() throws Exception {
		final String[] parts = Jwt.sign(new JsonObject().put("sub", "u1"), KEYS.getPrivate(), "k1").split("\\.");
		final String forged = parts[0] + "." + b64("{\"sub\":\"admin\"}") + "." + parts[2];
		Jwt.verify(Jwt.decode(forged), KEYS.getPublic());
	}

	@Test
	public void rejectsAlgNone() throws Exception {
		final String token = b64("{\"alg\":\"none\"}") + "." + b64("{\"sub\":\"admin\"}") + ".";
		try {
			Jwt.verify(Jwt.decode(token), KEYS.getPublic());
			fail();
		} catch (LtiException e) {
			assertEquals("unsupported.jwt.alg", e.getMessage());
		}
	}

	@Test
	public void rejectsExpiredAndFutureTokens() {
		assertThrows(LtiException.class, () -> Jwt.checkTimes(new JsonObject().put("exp", 100), 1000, 60));
		assertThrows(LtiException.class, () -> Jwt.checkTimes(new JsonObject(), 1000, 60));
		assertThrows(LtiException.class, () -> Jwt.checkTimes(new JsonObject().put("exp", 5000).put("iat", 2000), 1000, 60));
	}

	@Test
	public void rejectsMalformedTokens() {
		assertThrows(LtiException.class, () -> Jwt.decode(null));
		assertThrows(LtiException.class, () -> Jwt.decode("abc"));
		assertThrows(LtiException.class, () -> Jwt.decode("a.b.c"));
	}

	@Test
	public void audienceMayBeStringOrArray() {
		assertTrue(Jwt.audienceContains(new JsonObject().put("aud", "x"), "x"));
		assertTrue(Jwt.audienceContains(new JsonObject().put("aud", new JsonArray().add("y").add("x")), "x"));
		assertFalse(Jwt.audienceContains(new JsonObject().put("aud", "y"), "x"));
		assertFalse(Jwt.audienceContains(new JsonObject(), "x"));
	}

	@Test
	public void jwkRoundTripAndSelection() throws Exception {
		final JsonObject jwk = Jwk.toJwk((RSAPublicKey) KEYS.getPublic(), "k1");
		assertEquals("RSA", jwk.getString("kty"));
		assertEquals(KEYS.getPublic(), Jwk.toPublicKey(jwk));
		final JsonObject other = Jwk.toJwk((RSAPublicKey) OTHER.getPublic(), "k2");
		final JsonObject jwks = new JsonObject().put("keys", new JsonArray().add(jwk).add(other));
		assertEquals("k2", Jwk.select(jwks, "k2").getString("kid"));
		assertThrows(LtiException.class, () -> Jwk.select(jwks, "unknown"));
		// Sans kid, une seule clé RSA est acceptée sans ambiguïté.
		assertThrows(LtiException.class, () -> Jwk.select(jwks, null));
		assertEquals("k1", Jwk.select(new JsonObject().put("keys", new JsonArray().add(jwk)), null).getString("kid"));
	}

	@Test
	public void keyManagerLoadsPkcs8PemAndPublishesJwks() throws Exception {
		final String pem = "-----BEGIN PRIVATE KEY-----\n"
				+ Base64.getMimeEncoder().encodeToString(KEYS.getPrivate().getEncoded())
				+ "\n-----END PRIVATE KEY-----";
		final KeyManager manager = KeyManager.fromConfig(new JsonObject().put("private-key", pem).put("kid", "prod-1")
				.put("previous-public-keys", new JsonArray().add(Jwk.toJwk((RSAPublicKey) OTHER.getPublic(), "old"))));
		assertEquals(KEYS.getPublic(), manager.getPublicKey());
		final JsonArray keys = manager.jwks().getJsonArray("keys");
		assertEquals(2, keys.size());
		assertEquals("prod-1", keys.getJsonObject(0).getString("kid"));
		assertFalse(keys.getJsonObject(0).containsKey("d"));
		Jwt.verify(Jwt.decode(manager.sign(new JsonObject().put("a", 1))), KEYS.getPublic());
	}

	@Test
	public void pseudonymIsStablePerToolAndOpaque() {
		final String a = Hashes.pseudonym("salt-a", "user-1");
		assertEquals(a, Hashes.pseudonym("salt-a", "user-1"));
		assertNotEquals(a, Hashes.pseudonym("salt-b", "user-1"));
		assertFalse(a.contains("user-1"));
		assertEquals(64, a.length());
	}

	private static String b64(String s) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
	}
}
