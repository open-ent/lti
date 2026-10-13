package fr.openent.lti.core;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.util.List;

/**
 * Construction des claims de l'id_token d'un lancement LTI 1.3
 * (LtiResourceLinkRequest ou LtiDeepLinkingRequest), avec les services AGS et NRPS.
 */
public class LaunchRequest {

	public String issuer;
	public String clientId;
	public String deploymentId;
	public String subject;
	public String nonce;
	public String messageType = Lti13.MSG_RESOURCE_LINK;
	public String targetLinkUri;
	public String resourceLinkId;
	public String resourceLinkTitle;
	public String contextId;
	public String contextLabel;
	public String contextTitle;
	public List<String> roles;
	public List<String> mentorScope;
	public String givenName;
	public String familyName;
	public String name;
	public String email;
	public String locale;
	public String documentTarget = "window";
	public String returnUrl;
	public String platformGuid;
	public String platformName;
	public JsonObject custom;
	public JsonObject agsEndpoint;
	public String nrpsMembershipsUrl;
	public JsonObject deepLinkingSettings;
	public long issuedAt;
	public long ttlSeconds = 300;

	public JsonObject toClaims() {
		require(issuer, "issuer");
		require(clientId, "clientId");
		require(deploymentId, "deploymentId");
		require(subject, "subject");
		require(nonce, "nonce");
		require(targetLinkUri, "targetLinkUri");
		if (roles == null) {
			throw new IllegalStateException("roles is required");
		}
		final JsonObject claims = new JsonObject()
				.put("iss", issuer)
				.put("aud", clientId)
				.put("azp", clientId)
				.put("sub", subject)
				.put("nonce", nonce)
				.put("iat", issuedAt)
				.put("exp", issuedAt + ttlSeconds)
				.put(Lti13.CLAIM_MESSAGE_TYPE, messageType)
				.put(Lti13.CLAIM_VERSION, Lti13.VERSION)
				.put(Lti13.CLAIM_DEPLOYMENT_ID, deploymentId)
				.put(Lti13.CLAIM_TARGET_LINK_URI, targetLinkUri)
				.put(Lti13.CLAIM_ROLES, new JsonArray(roles))
				.put(Lti13.CLAIM_TOOL_PLATFORM, new JsonObject()
						.put("guid", platformGuid)
						.put("name", platformName)
						.put("product_family_code", "open-ent"))
				.put(Lti13.CLAIM_LAUNCH_PRESENTATION, launchPresentation());

		if (Lti13.MSG_RESOURCE_LINK.equals(messageType)) {
			require(resourceLinkId, "resourceLinkId");
			final JsonObject link = new JsonObject().put("id", resourceLinkId);
			if (resourceLinkTitle != null) {
				link.put("title", resourceLinkTitle);
			}
			claims.put(Lti13.CLAIM_RESOURCE_LINK, link);
		} else if (Lti13.MSG_DEEP_LINKING.equals(messageType)) {
			if (deepLinkingSettings == null) {
				throw new IllegalStateException("deepLinkingSettings is required for " + messageType);
			}
			claims.put(Lti13.CLAIM_DL_SETTINGS, deepLinkingSettings);
		} else {
			throw new IllegalStateException("Unsupported message type " + messageType);
		}

		if (contextId != null) {
			final JsonObject context = new JsonObject()
					.put("id", contextId)
					.put("type", new JsonArray().add(Lti13.CONTEXT_TYPE_COURSE_SECTION));
			if (contextLabel != null) {
				context.put("label", contextLabel);
			}
			if (contextTitle != null) {
				context.put("title", contextTitle);
			}
			claims.put(Lti13.CLAIM_CONTEXT, context);
		}
		if (mentorScope != null && !mentorScope.isEmpty()) {
			claims.put(Lti13.CLAIM_ROLE_SCOPE_MENTOR, new JsonArray(mentorScope));
		}
		putIfPresent(claims, "given_name", givenName);
		putIfPresent(claims, "family_name", familyName);
		putIfPresent(claims, "name", name);
		putIfPresent(claims, "email", email);
		putIfPresent(claims, "locale", locale);
		if (custom != null && !custom.isEmpty()) {
			claims.put(Lti13.CLAIM_CUSTOM, custom);
		}
		if (agsEndpoint != null) {
			claims.put(Lti13.CLAIM_AGS_ENDPOINT, agsEndpoint);
		}
		if (nrpsMembershipsUrl != null) {
			claims.put(Lti13.CLAIM_NRPS, new JsonObject()
					.put("context_memberships_url", nrpsMembershipsUrl)
					.put("service_versions", new JsonArray().add("2.0")));
		}
		return claims;
	}

	private JsonObject launchPresentation() {
		final JsonObject lp = new JsonObject().put("document_target", documentTarget);
		putIfPresent(lp, "return_url", returnUrl);
		putIfPresent(lp, "locale", locale);
		return lp;
	}

	/** Paramètres Deep Linking 2.0 annoncés à l'outil. */
	public static JsonObject deepLinkingSettings(String returnUrl, String data) {
		return new JsonObject()
				.put("deep_link_return_url", returnUrl)
				.put("accept_types", new JsonArray().add("ltiResourceLink").add("link"))
				.put("accept_presentation_document_targets", new JsonArray().add("iframe").add("window"))
				.put("accept_multiple", true)
				.put("auto_create", true)
				.put("data", data);
	}

	private static void putIfPresent(JsonObject o, String key, String value) {
		if (value != null && !value.isEmpty()) {
			o.put(key, value);
		}
	}

	private static void require(String value, String name) {
		if (value == null || value.isEmpty()) {
			throw new IllegalStateException(name + " is required");
		}
	}
}
