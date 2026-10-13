package fr.openent.lti.core;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.util.Arrays;
import java.util.List;

/** Validation de l'enregistrement d'un outil LTI par l'administrateur. */
public final class ToolValidator {

	public static final List<String> SUPPORTED_SCOPES = Arrays.asList(
			Lti13.SCOPE_LINEITEM, Lti13.SCOPE_LINEITEM_READONLY, Lti13.SCOPE_RESULT_READONLY,
			Lti13.SCOPE_SCORE, Lti13.SCOPE_NRPS);

	private ToolValidator() {
	}

	public static JsonObject validate(JsonObject body) throws LtiException {
		if (body == null) {
			throw new LtiException("invalid.tool");
		}
		final String name = body.getString("name");
		if (name == null || name.trim().isEmpty() || name.length() > 255) {
			throw new LtiException("invalid.tool.name");
		}
		final String initiation = requireUrl(body, "oidc_initiation_url");
		final String target = requireUrl(body, "target_link_uri");
		final JsonArray redirects = body.getJsonArray("redirect_uris", new JsonArray().add(target));
		if (redirects.isEmpty()) {
			throw new LtiException("invalid.tool.redirect_uris");
		}
		for (Object o : redirects) {
			if (!(o instanceof String) || !DeepLinkResponse.isHttpUrl((String) o)) {
				throw new LtiException("invalid.tool.redirect_uris");
			}
		}
		final String deepLinking = body.getString("deep_linking_url");
		if (deepLinking != null && !DeepLinkResponse.isHttpUrl(deepLinking)) {
			throw new LtiException("invalid.tool.deep_linking_url");
		}
		final String jwksUrl = body.getString("jwks_url");
		final JsonObject publicJwk = body.getJsonObject("public_jwk");
		if ((jwksUrl == null || !DeepLinkResponse.isHttpUrl(jwksUrl)) && publicJwk == null) {
			throw new LtiException("invalid.tool.key");
		}
		final JsonArray scopes = body.getJsonArray("scopes", new JsonArray());
		for (Object o : scopes) {
			if (!SUPPORTED_SCOPES.contains(o)) {
				throw new LtiException("invalid.tool.scopes");
			}
		}
		final String documentTarget = body.getString("document_target", "window");
		if (!"window".equals(documentTarget) && !"iframe".equals(documentTarget)) {
			throw new LtiException("invalid.tool.document_target");
		}
		final JsonObject custom = body.getJsonObject("custom", new JsonObject());
		for (String key : custom.fieldNames()) {
			if (!(custom.getValue(key) instanceof String)) {
				throw new LtiException("invalid.tool.custom");
			}
		}
		return new JsonObject()
				.put("name", name.trim())
				.put("description", body.getString("description"))
				.put("icon_url", body.getString("icon_url"))
				.put("oidc_initiation_url", initiation)
				.put("target_link_uri", target)
				.put("redirect_uris", redirects)
				.put("deep_linking_url", deepLinking)
				.put("jwks_url", jwksUrl)
				.put("public_jwk", publicJwk)
				.put("scopes", scopes)
				.put("custom", custom)
				.put("share_name", body.getBoolean("share_name", false))
				.put("share_email", body.getBoolean("share_email", false))
				.put("document_target", documentTarget)
				.put("enabled", body.getBoolean("enabled", true));
	}

	private static String requireUrl(JsonObject body, String key) throws LtiException {
		final String url = body.getString(key);
		if (url == null || !DeepLinkResponse.isHttpUrl(url)) {
			throw new LtiException("invalid.tool." + key);
		}
		return url;
	}
}
