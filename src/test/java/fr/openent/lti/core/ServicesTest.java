package fr.openent.lti.core;

import fr.openent.lti.security.KeyManager;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class ServicesTest {

	private static final String ISSUER = "https://ent.example.org";
	private final KeyManager keys = KeyManager.fromConfig(new JsonObject());
	private final PlatformTokens tokens = new PlatformTokens(keys, ISSUER);

	@Test
	public void accessTokenChecksScopesAndType() throws Exception {
		final String token = tokens.issueAccessToken("tool-1", Arrays.asList(Lti13.SCOPE_SCORE), 1000, 3600);
		assertEquals("tool-1", tokens.verifyAccessToken("Bearer " + token, 1100, Lti13.SCOPE_SCORE));
		try {
			tokens.verifyAccessToken("Bearer " + token, 1100, Lti13.SCOPE_NRPS);
			fail();
		} catch (LtiException e) {
			assertEquals(403, e.getStatus());
		}
		assertThrows(LtiException.class, () -> tokens.verifyAccessToken("Bearer " + token, 9000, Lti13.SCOPE_SCORE));
		assertThrows(LtiException.class, () -> tokens.verifyAccessToken(null, 1100, Lti13.SCOPE_SCORE));
		// Un lti_message_hint ne peut pas servir de jeton d'accès.
		final String hint = tokens.issue(PlatformTokens.TYP_MESSAGE_HINT,
				new JsonObject().put("sub", "tool-1").put("scope", Lti13.SCOPE_SCORE), 1000, 300);
		assertThrows(LtiException.class, () -> tokens.verifyAccessToken("Bearer " + hint, 1100, Lti13.SCOPE_SCORE));
		// Un jeton signé par une autre plateforme est refusé.
		final PlatformTokens other = new PlatformTokens(KeyManager.fromConfig(new JsonObject()), ISSUER);
		final String foreign = other.issueAccessToken("tool-1", Arrays.asList(Lti13.SCOPE_SCORE), 1000, 3600);
		assertThrows(LtiException.class, () -> tokens.verifyAccessToken("Bearer " + foreign, 1100, Lti13.SCOPE_SCORE));
	}

	@Test
	public void grantedScopesAreLimitedToToolScopes() {
		final List<String> granted = PlatformTokens.grant(
				Lti13.SCOPE_SCORE + " " + Lti13.SCOPE_NRPS + " https://evil/scope",
				new JsonArray().add(Lti13.SCOPE_SCORE));
		assertEquals(Arrays.asList(Lti13.SCOPE_SCORE), granted);
		assertTrue(PlatformTokens.grant(null, new JsonArray()).isEmpty());
	}

	@Test
	public void clientAssertionValidation() throws Exception {
		final String endpoint = ISSUER + "/lti/token";
		final JsonObject ok = new JsonObject().put("iss", "tool-1").put("sub", "tool-1").put("aud", endpoint)
				.put("iat", 1000).put("exp", 1300).put("jti", "j1");
		assertEquals("j1", ClientAssertion.validate(ok, "tool-1", 1100, endpoint, ISSUER));
		assertThrows(LtiException.class, () -> ClientAssertion.validate(ok.copy().put("sub", "tool-2"), "tool-1", 1100, endpoint));
		assertThrows(LtiException.class, () -> ClientAssertion.validate(ok.copy().put("aud", "https://other"), "tool-1", 1100, endpoint));
		assertThrows(LtiException.class, () -> ClientAssertion.validate(ok.copy().put("exp", 900), "tool-1", 1100, endpoint));
		assertThrows(LtiException.class, () -> ClientAssertion.validate(ok.copy().put("exp", 99999), "tool-1", 1100, endpoint));
		final JsonObject noJti = ok.copy();
		noJti.remove("jti");
		assertThrows(LtiException.class, () -> ClientAssertion.validate(noJti, "tool-1", 1100, endpoint));
	}

	@Test
	public void deepLinkResponseValidation() throws Exception {
		final JsonObject payload = new JsonObject()
				.put("iss", "tool-1").put("aud", ISSUER)
				.put(Lti13.CLAIM_MESSAGE_TYPE, Lti13.MSG_DEEP_LINKING_RESPONSE)
				.put(Lti13.CLAIM_VERSION, "1.3.0")
				.put(Lti13.CLAIM_DEPLOYMENT_ID, "dep-1")
				.put(Lti13.CLAIM_DL_DATA, "data")
				.put(Lti13.CLAIM_DL_CONTENT_ITEMS, new JsonArray()
						.add(new JsonObject().put("type", "ltiResourceLink").put("title", "Quiz")
								.put("url", "https://tool/quiz/1").put("custom", new JsonObject().put("quiz", 1))
								.put("lineItem", new JsonObject().put("scoreMaximum", 20).put("label", "Quiz 1")))
						.add(new JsonObject().put("type", "link").put("url", "javascript:alert(1)"))
						.add(new JsonObject().put("type", "html").put("html", "<b>x</b>"))
						.add(new JsonObject().put("type", "ltiResourceLink").put("title", "Default url")));
		final DeepLinkResponse response = DeepLinkResponse.parse(payload, "tool-1", ISSUER, "dep-1", "data");
		assertEquals(2, response.items.size());
		assertEquals(2, response.ignored);
		assertEquals("1", response.items.get(0).getJsonObject("custom").getString("quiz"));
		assertEquals(20.0, response.items.get(0).getJsonObject("lineItem").getDouble("scoreMaximum"), 0);
		assertNull(response.items.get(1).getString("url"));

		assertThrows(LtiException.class, () -> DeepLinkResponse.parse(payload, "tool-1", ISSUER, "dep-2", "data"));
		assertThrows(LtiException.class, () -> DeepLinkResponse.parse(payload, "tool-1", ISSUER, "dep-1", "other"));
		assertThrows(LtiException.class, () -> DeepLinkResponse.parse(payload, "tool-2", ISSUER, "dep-1", "data"));
		assertThrows(LtiException.class, () -> DeepLinkResponse.parse(payload.copy().put("aud", "https://x"),
				"tool-1", ISSUER, "dep-1", "data"));
	}

	@Test
	public void scoreValidation() throws Exception {
		final JsonObject score = new JsonObject().put("userId", "sub").put("timestamp", "2026-10-13T10:00:00.000Z")
				.put("activityProgress", "Completed").put("gradingProgress", "FullyGraded")
				.put("scoreGiven", 15).put("scoreMaximum", 20).put("comment", "Bien");
		final JsonObject valid = Ags.validateScore(score);
		assertEquals(15.0, valid.getDouble("scoreGiven"), 0);
		assertEquals(7.5, Ags.normalized(valid, 10), 1e-9);
		assertThrows(LtiException.class, () -> Ags.validateScore(score.copy().put("timestamp", "hier")));
		assertThrows(LtiException.class, () -> Ags.validateScore(score.copy().put("gradingProgress", "Done")));
		assertThrows(LtiException.class, () -> Ags.validateScore(score.copy().put("scoreGiven", -1)));
		assertThrows(LtiException.class, () -> Ags.validateScore(score.copy().put("scoreMaximum", 0)));
		final JsonObject noScore = score.copy();
		noScore.remove("scoreGiven");
		noScore.remove("scoreMaximum");
		assertNull(Ags.normalized(Ags.validateScore(noScore.put("gradingProgress", "Pending")), 20));
	}

	@Test
	public void lineItemValidationAndSerialization() throws Exception {
		final JsonObject item = Ags.validateLineItem(new JsonObject().put("label", " Chapitre 1 ").put("scoreMaximum", 20)
				.put("tag", "quiz").put("endDateTime", "2026-12-01T00:00:00Z"));
		assertEquals("Chapitre 1", item.getString("label"));
		assertThrows(LtiException.class, () -> Ags.validateLineItem(new JsonObject().put("label", "x").put("scoreMaximum", 0)));
		assertThrows(LtiException.class, () -> Ags.validateLineItem(new JsonObject().put("scoreMaximum", 10)));
		assertThrows(LtiException.class, () -> Ags.validateLineItem(new JsonObject().put("label", "x")
				.put("scoreMaximum", 10).put("startDateTime", "demain")));

		final JsonObject json = Ags.lineItemJson(new JsonObject().put("id", 3).put("label", "L")
				.put("score_maximum", "20").put("tag", "t"), "https://ent/lti/ags/c/lineitems/3");
		assertEquals("https://ent/lti/ags/c/lineitems/3", json.getString("id"));
		assertEquals(20.0, json.getDouble("scoreMaximum"), 0);
		final JsonObject result = Ags.resultJson(new JsonObject().put("score_given", 12).put("score_maximum", 20),
				"https://ent/lti/ags/c/lineitems/3", "sub-1");
		assertEquals("sub-1", result.getString("userId"));
		assertEquals(12.0, result.getDouble("resultScore"), 0);
	}

	@Test
	public void nrpsMemberHonoursSharingFlags() {
		final JsonObject row = new JsonObject().put("id", "u1").put("profile", "Teacher").put("firstName", "Ada")
				.put("lastName", "Lovelace").put("displayName", "Ada Lovelace").put("email", "ada@example.org");
		final JsonObject hidden = Nrps.member(row, "sub-1", false, false);
		assertEquals("sub-1", hidden.getString("user_id"));
		assertEquals(LtiRoles.INSTRUCTOR, hidden.getJsonArray("roles").getString(0));
		assertFalse(hidden.containsKey("name"));
		assertFalse(hidden.containsKey("email"));
		assertFalse(hidden.encode().contains("u1"));
		final JsonObject shared = Nrps.member(row, "sub-1", true, true);
		assertEquals("Ada Lovelace", shared.getString("name"));
		assertEquals("ada@example.org", shared.getString("email"));
	}

	@Test
	public void toolValidation() throws Exception {
		final JsonObject body = new JsonObject().put("name", "Moodle")
				.put("oidc_initiation_url", "https://moodle/lti/login")
				.put("target_link_uri", "https://moodle/lti/launch")
				.put("jwks_url", "https://moodle/lti/certs")
				.put("scopes", new JsonArray().add(Lti13.SCOPE_SCORE));
		final JsonObject tool = ToolValidator.validate(body);
		assertEquals("https://moodle/lti/launch", tool.getJsonArray("redirect_uris").getString(0));
		assertFalse(tool.getBoolean("share_email"));
		assertThrows(LtiException.class, () -> ToolValidator.validate(body.copy().put("scopes", new JsonArray().add("admin"))));
		assertThrows(LtiException.class, () -> ToolValidator.validate(body.copy().put("oidc_initiation_url", "ftp://x")));
		final JsonObject noKey = body.copy();
		noKey.remove("jwks_url");
		assertThrows(LtiException.class, () -> ToolValidator.validate(noKey));
		assertThrows(LtiException.class, () -> ToolValidator.validate(body.copy()
				.put("redirect_uris", new JsonArray().add("javascript:alert(1)"))));
	}
}
