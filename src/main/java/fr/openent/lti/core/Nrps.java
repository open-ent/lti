package fr.openent.lti.core;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/** Sérialisation LTI Names and Role Provisioning Services 2.0. */
public final class Nrps {

	private Nrps() {
	}

	/**
	 * @param member ligne annuaire : id, profile, firstName, lastName, displayName, email
	 * @param ltiUserId identifiant pseudonyme de l'utilisateur pour cet outil
	 */
	public static JsonObject member(JsonObject member, String ltiUserId, boolean shareName, boolean shareEmail) {
		final JsonObject json = new JsonObject()
				.put("status", "Active")
				.put("user_id", ltiUserId)
				.put("roles", new JsonArray().add(LtiRoles.contextRole(member.getString("profile"))));
		if (shareName) {
			putIfPresent(json, "given_name", member.getString("firstName"));
			putIfPresent(json, "family_name", member.getString("lastName"));
			putIfPresent(json, "name", member.getString("displayName"));
		}
		if (shareEmail) {
			putIfPresent(json, "email", member.getString("email"));
		}
		return json;
	}

	public static JsonObject container(String url, JsonObject context, JsonArray members) {
		return new JsonObject()
				.put("id", url)
				.put("context", context)
				.put("members", members);
	}

	private static void putIfPresent(JsonObject o, String key, String value) {
		if (value != null && !value.isEmpty()) {
			o.put(key, value);
		}
	}
}
