package fr.openent.lti.core;

import io.vertx.core.json.JsonObject;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;

public class LaunchRequestTest {

	private static LaunchRequest base() {
		final LaunchRequest r = new LaunchRequest();
		r.issuer = "https://ent.example.org";
		r.clientId = "tool-1";
		r.deploymentId = "dep-1";
		r.subject = "sub-1";
		r.nonce = "n-1";
		r.targetLinkUri = "https://tool.example.org/launch";
		r.resourceLinkId = "link-1";
		r.roles = LtiRoles.launchRoles("Student", false);
		r.issuedAt = 1000;
		r.platformGuid = r.issuer;
		r.platformName = "Open ENT";
		return r;
	}

	@Test
	public void resourceLinkRequestHasRequiredClaims() {
		final LaunchRequest r = base();
		r.contextId = "class-1";
		r.contextTitle = "6eA";
		r.givenName = "Ada";
		final JsonObject claims = r.toClaims();
		assertEquals("https://ent.example.org", claims.getString("iss"));
		assertEquals("tool-1", claims.getString("aud"));
		assertEquals("tool-1", claims.getString("azp"));
		assertEquals("sub-1", claims.getString("sub"));
		assertEquals("n-1", claims.getString("nonce"));
		assertEquals(1300L, (long) claims.getLong("exp"));
		assertEquals("LtiResourceLinkRequest", claims.getString(Lti13.CLAIM_MESSAGE_TYPE));
		assertEquals("1.3.0", claims.getString(Lti13.CLAIM_VERSION));
		assertEquals("dep-1", claims.getString(Lti13.CLAIM_DEPLOYMENT_ID));
		assertEquals("https://tool.example.org/launch", claims.getString(Lti13.CLAIM_TARGET_LINK_URI));
		assertEquals("link-1", claims.getJsonObject(Lti13.CLAIM_RESOURCE_LINK).getString("id"));
		assertTrue(claims.getJsonArray(Lti13.CLAIM_ROLES).contains(LtiRoles.LEARNER));
		assertEquals("class-1", claims.getJsonObject(Lti13.CLAIM_CONTEXT).getString("id"));
		assertEquals("Ada", claims.getString("given_name"));
		assertFalse("email non partagé", claims.containsKey("email"));
		assertFalse(claims.containsKey(Lti13.CLAIM_AGS_ENDPOINT));
		assertFalse(claims.containsKey(Lti13.CLAIM_NRPS));
	}

	@Test
	public void servicesAndMentorScopeAreIncluded() {
		final LaunchRequest r = base();
		r.agsEndpoint = new JsonObject().put("lineitems", "https://ent/lti/ags/c/lineitems");
		r.nrpsMembershipsUrl = "https://ent/lti/nrps/c/memberships";
		r.mentorScope = Arrays.asList("child-sub");
		final JsonObject claims = r.toClaims();
		assertEquals("https://ent/lti/ags/c/lineitems",
				claims.getJsonObject(Lti13.CLAIM_AGS_ENDPOINT).getString("lineitems"));
		assertEquals("2.0", claims.getJsonObject(Lti13.CLAIM_NRPS).getJsonArray("service_versions").getString(0));
		assertEquals("child-sub", claims.getJsonArray(Lti13.CLAIM_ROLE_SCOPE_MENTOR).getString(0));
	}

	@Test
	public void deepLinkingRequestCarriesSettingsAndNoResourceLink() {
		final LaunchRequest r = base();
		r.messageType = Lti13.MSG_DEEP_LINKING;
		r.resourceLinkId = null;
		r.deepLinkingSettings = LaunchRequest.deepLinkingSettings("https://ent/lti/deeplink/return", "opaque");
		final JsonObject claims = r.toClaims();
		assertFalse(claims.containsKey(Lti13.CLAIM_RESOURCE_LINK));
		final JsonObject settings = claims.getJsonObject(Lti13.CLAIM_DL_SETTINGS);
		assertEquals("https://ent/lti/deeplink/return", settings.getString("deep_link_return_url"));
		assertEquals("opaque", settings.getString("data"));
		assertTrue(settings.getJsonArray("accept_types").contains("ltiResourceLink"));
	}

	@Test(expected = IllegalStateException.class)
	public void resourceLinkIsMandatory() {
		final LaunchRequest r = base();
		r.resourceLinkId = null;
		r.toClaims();
	}

	@Test
	public void rolesMapping() {
		assertEquals(LtiRoles.INSTRUCTOR, LtiRoles.contextRole("Teacher"));
		assertEquals(LtiRoles.LEARNER, LtiRoles.contextRole("Student"));
		assertEquals(LtiRoles.MENTOR, LtiRoles.contextRole("Relative"));
		assertEquals(LtiRoles.MENTOR, LtiRoles.contextRole("Personnel"));
		assertEquals(LtiRoles.MEMBER, LtiRoles.contextRole("Guest"));
		assertTrue(LtiRoles.launchRoles("Teacher", true).contains(LtiRoles.ADMINISTRATOR));
		assertFalse(LtiRoles.launchRoles("Teacher", false).contains(LtiRoles.ADMINISTRATOR));
		assertTrue(LtiRoles.matches(LtiRoles.LEARNER, "Learner"));
		assertTrue(LtiRoles.matches(LtiRoles.LEARNER, LtiRoles.LEARNER));
		assertTrue(LtiRoles.matches(LtiRoles.LEARNER, null));
		assertFalse(LtiRoles.matches(LtiRoles.LEARNER, "Instructor"));
	}

	@Test
	public void autoPostFormEscapesValues() {
		final java.util.Map<String, String> fields = new java.util.LinkedHashMap<>();
		fields.put("id_token", "a.b.c");
		fields.put("state", "\"><script>alert(1)</script>");
		final String html = Html.autoPostForm("https://tool/launch?x=1&y=2", fields);
		assertTrue(html.contains("action=\"https://tool/launch?x=1&amp;y=2\""));
		assertFalse(html.contains("<script>alert"));
		assertTrue(html.contains("&quot;&gt;&lt;script&gt;"));
	}
}
