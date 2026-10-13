package fr.openent.lti.core;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/** Lecture et validation d'un LtiDeepLinkingResponse (claims déjà authentifiés par signature). */
public final class DeepLinkResponse {

	public final List<JsonObject> items = new ArrayList<>();
	public int ignored;
	public String message;
	public String errorMessage;

	private DeepLinkResponse() {
	}

	public static DeepLinkResponse parse(JsonObject payload, String clientId, String platformIssuer,
			String expectedDeploymentId, String expectedData) throws LtiException {
		if (!clientId.equals(payload.getString("iss"))) {
			throw new LtiException(401, "invalid.issuer");
		}
		if (!fr.openent.lti.security.Jwt.audienceContains(payload, platformIssuer)) {
			throw new LtiException(401, "invalid.audience");
		}
		if (!Lti13.MSG_DEEP_LINKING_RESPONSE.equals(payload.getString(Lti13.CLAIM_MESSAGE_TYPE))) {
			throw new LtiException("invalid.message.type");
		}
		if (!Lti13.VERSION.equals(payload.getString(Lti13.CLAIM_VERSION))) {
			throw new LtiException("invalid.lti.version");
		}
		if (!expectedDeploymentId.equals(payload.getString(Lti13.CLAIM_DEPLOYMENT_ID))) {
			throw new LtiException("invalid.deployment");
		}
		if (expectedData != null && !expectedData.equals(payload.getString(Lti13.CLAIM_DL_DATA))) {
			throw new LtiException("invalid.deep.linking.data");
		}
		final DeepLinkResponse response = new DeepLinkResponse();
		response.message = payload.getString(Lti13.CLAIM_DL_MSG);
		response.errorMessage = payload.getString(Lti13.CLAIM_DL_ERRORMSG);
		final JsonArray contentItems = payload.getJsonArray(Lti13.CLAIM_DL_CONTENT_ITEMS, new JsonArray());
		for (Object o : contentItems) {
			final JsonObject item = o instanceof JsonObject ? normalize((JsonObject) o) : null;
			if (item == null) {
				response.ignored++;
			} else {
				response.items.add(item);
			}
		}
		return response;
	}

	/** Ne conserve que ltiResourceLink et link avec une URL http(s) valide ; renvoie null sinon. */
	static JsonObject normalize(JsonObject item) {
		final String type = item.getString("type");
		if (!"ltiResourceLink".equals(type) && !"link".equals(type)) {
			return null;
		}
		final String url = item.getString("url");
		if (url == null ? "link".equals(type) : !isHttpUrl(url)) {
			return null;
		}
		final JsonObject out = new JsonObject()
				.put("type", type)
				.put("title", truncate(item.getString("title"), 255))
				.put("text", truncate(item.getString("text"), 2000))
				.put("url", url);
		final Object custom = item.getValue("custom");
		out.put("custom", custom instanceof JsonObject ? stringValues((JsonObject) custom) : new JsonObject());
		final JsonObject lineItem = item.getJsonObject("lineItem");
		if ("ltiResourceLink".equals(type) && lineItem != null) {
			final Object max = lineItem.getValue("scoreMaximum");
			if (max instanceof Number && ((Number) max).doubleValue() > 0) {
				out.put("lineItem", new JsonObject()
						.put("scoreMaximum", ((Number) max).doubleValue())
						.put("label", truncate(lineItem.getString("label", out.getString("title")), 255))
						.put("resourceId", lineItem.getString("resourceId"))
						.put("tag", lineItem.getString("tag")));
			}
		}
		return out;
	}

	static boolean isHttpUrl(String url) {
		try {
			final URI uri = new URI(url);
			return ("https".equalsIgnoreCase(uri.getScheme()) || "http".equalsIgnoreCase(uri.getScheme()))
					&& uri.getHost() != null;
		} catch (Exception e) {
			return false;
		}
	}

	private static JsonObject stringValues(JsonObject custom) {
		final JsonObject out = new JsonObject();
		for (String key : custom.fieldNames()) {
			final Object v = custom.getValue(key);
			if (v != null && !(v instanceof JsonObject) && !(v instanceof JsonArray)) {
				out.put(key, String.valueOf(v));
			}
		}
		return out;
	}

	private static String truncate(String s, int max) {
		return s == null || s.length() <= max ? s : s.substring(0, max);
	}
}
