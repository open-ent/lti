package fr.openent.lti.service;

import fr.openent.lti.security.Hashes;
import io.vertx.core.Future;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Outils, déploiements par structure, contextes et pseudonymes. */
public class ToolRepository {

	private static final String TOOL_COLUMNS = "id, name, description, icon_url, oidc_initiation_url, target_link_uri, " +
			"redirect_uris, deep_linking_url, jwks_url, public_jwk, scopes, custom, share_name, share_email, " +
			"document_target, subject_salt, enabled";
	private static final String PUBLIC_TOOL_COLUMNS = "id, name, description, icon_url, oidc_initiation_url, " +
			"target_link_uri, redirect_uris, deep_linking_url, jwks_url, public_jwk, scopes, custom, share_name, " +
			"share_email, document_target, enabled, created_at, updated_at";

	public Future<JsonObject> findTool(String toolId) {
		return Db.sqlOne("SELECT " + TOOL_COLUMNS + " FROM lti.tools WHERE id = ?", new JsonArray().add(toolId));
	}

	public Future<JsonArray> listTools() {
		return Db.sql("SELECT " + PUBLIC_TOOL_COLUMNS + " FROM lti.tools ORDER BY name", new JsonArray());
	}

	public Future<JsonObject> createTool(JsonObject tool) {
		final String id = UUID.randomUUID().toString();
		final String query = "INSERT INTO lti.tools (id, name, description, icon_url, oidc_initiation_url, target_link_uri, " +
				"redirect_uris, deep_linking_url, jwks_url, public_jwk, scopes, custom, share_name, share_email, " +
				"document_target, subject_salt, enabled) VALUES (?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?::jsonb, ?::jsonb, " +
				"?::jsonb, ?, ?, ?, ?, ?) RETURNING " + PUBLIC_TOOL_COLUMNS;
		final JsonArray params = new JsonArray().add(id);
		addToolParams(params, tool);
		params.add(Hashes.randomHex(32)).add(tool.getBoolean("enabled"));
		return Db.sqlOne(query, params);
	}

	public Future<JsonObject> updateTool(String id, JsonObject tool) {
		final String query = "UPDATE lti.tools SET name = ?, description = ?, icon_url = ?, oidc_initiation_url = ?, " +
				"target_link_uri = ?, redirect_uris = ?::jsonb, deep_linking_url = ?, jwks_url = ?, public_jwk = ?::jsonb, " +
				"scopes = ?::jsonb, custom = ?::jsonb, share_name = ?, share_email = ?, document_target = ?, enabled = ?, " +
				"updated_at = NOW() WHERE id = ? RETURNING " + PUBLIC_TOOL_COLUMNS;
		final JsonArray params = new JsonArray();
		addToolParams(params, tool);
		params.add(tool.getBoolean("enabled")).add(id);
		return Db.sqlOne(query, params);
	}

	private static void addToolParams(JsonArray params, JsonObject tool) {
		params.add(tool.getString("name"))
				.add(tool.getString("description"))
				.add(tool.getString("icon_url"))
				.add(tool.getString("oidc_initiation_url"))
				.add(tool.getString("target_link_uri"))
				.add(Db.encode(tool.getJsonArray("redirect_uris")))
				.add(tool.getString("deep_linking_url"))
				.add(tool.getString("jwks_url"))
				.add(Db.encode(tool.getJsonObject("public_jwk")))
				.add(Db.encode(tool.getJsonArray("scopes")))
				.add(Db.encode(tool.getJsonObject("custom")))
				.add(tool.getBoolean("share_name"))
				.add(tool.getBoolean("share_email"))
				.add(tool.getString("document_target"));
	}

	public Future<JsonArray> deleteTool(String id) {
		return Db.sql("DELETE FROM lti.tools WHERE id = ? RETURNING id", new JsonArray().add(id));
	}

	/** Outils actifs déployés dans au moins une des structures données. */
	public Future<JsonArray> toolsForStructures(List<String> structures) {
		if (structures == null || structures.isEmpty()) {
			return Future.succeededFuture(new JsonArray());
		}
		final JsonArray params = new JsonArray(structures);
		return Db.sql("SELECT DISTINCT ON (t.id) t.id, t.name, t.description, t.icon_url, " +
				"(t.deep_linking_url IS NOT NULL) AS deep_linking, d.id AS deployment_id " +
				"FROM lti.deployments d JOIN lti.tools t ON t.id = d.tool_id " +
				"WHERE t.enabled = TRUE AND d.structure_id IN " + inPlaceholders(structures.size()) +
				" ORDER BY t.id, d.created_at", params);
	}

	public Future<JsonObject> findDeploymentForStructures(String toolId, List<String> structures) {
		if (structures == null || structures.isEmpty()) {
			return Future.succeededFuture(null);
		}
		final JsonArray params = new JsonArray().add(toolId);
		structures.forEach(params::add);
		return Db.sqlOne("SELECT id, tool_id, structure_id FROM lti.deployments WHERE tool_id = ? AND structure_id IN " +
				inPlaceholders(structures.size()) + " ORDER BY created_at LIMIT 1", params);
	}

	public Future<JsonArray> listDeployments(String structureId) {
		return Db.sql("SELECT t.id AS tool_id, t.name, t.description, t.enabled, d.id AS deployment_id " +
				"FROM lti.tools t LEFT JOIN lti.deployments d ON d.tool_id = t.id AND d.structure_id = ? " +
				"ORDER BY t.name", new JsonArray().add(structureId));
	}

	public Future<JsonObject> createDeployment(String toolId, String structureId, String userId) {
		return Db.sqlOne("INSERT INTO lti.deployments (id, tool_id, structure_id, created_by) VALUES (?, ?, ?, ?) " +
				"ON CONFLICT (tool_id, structure_id) DO UPDATE SET tool_id = EXCLUDED.tool_id " +
				"RETURNING id, tool_id, structure_id",
				new JsonArray().add(UUID.randomUUID().toString()).add(toolId).add(structureId).add(userId));
	}

	public Future<JsonArray> deleteDeployment(String structureId, String deploymentId) {
		return Db.sql("DELETE FROM lti.deployments WHERE id = ? AND structure_id = ? RETURNING id",
				new JsonArray().add(deploymentId).add(structureId));
	}

	public Future<Void> registerContext(String toolId, String contextId, String deploymentId) {
		return Db.sql("INSERT INTO lti.contexts (tool_id, context_id, deployment_id) VALUES (?, ?, ?) " +
				"ON CONFLICT (tool_id, context_id) DO NOTHING",
				new JsonArray().add(toolId).add(contextId).add(deploymentId)).mapEmpty();
	}

	public Future<Boolean> isContextRegistered(String toolId, String contextId) {
		return Db.sqlOne("SELECT 1 AS found FROM lti.contexts WHERE tool_id = ? AND context_id = ?",
				new JsonArray().add(toolId).add(contextId)).map(row -> row != null);
	}

	/** Enregistre les correspondances pseudonyme → utilisateur, par lots de 500. Les pseudonymes sont déterministes. */
	public Future<Void> registerSubjects(String toolId, Map<String, String> subToUserId) {
		final List<Map.Entry<String, String>> entries = new ArrayList<>(subToUserId.entrySet());
		Future<Void> chain = Future.succeededFuture();
		for (int start = 0; start < entries.size(); start += 500) {
			final List<Map.Entry<String, String>> batch = entries.subList(start, Math.min(start + 500, entries.size()));
			chain = chain.compose(v -> insertSubjects(toolId, batch));
		}
		return chain;
	}

	private Future<Void> insertSubjects(String toolId, List<Map.Entry<String, String>> batch) {
		final StringBuilder query = new StringBuilder("INSERT INTO lti.subjects (tool_id, sub, user_id) VALUES ");
		final JsonArray params = new JsonArray();
		for (int i = 0; i < batch.size(); i++) {
			query.append(i == 0 ? "" : ", ").append("(?, ?, ?)");
			params.add(toolId).add(batch.get(i).getKey()).add(batch.get(i).getValue());
		}
		query.append(" ON CONFLICT (tool_id, sub) DO NOTHING");
		return Db.sql(query.toString(), params).mapEmpty();
	}

	public Future<JsonObject> findDeployment(String deploymentId) {
		return Db.sqlOne("SELECT id, tool_id, structure_id FROM lti.deployments WHERE id = ?",
				new JsonArray().add(deploymentId));
	}

	public Future<String> resolveSubject(String toolId, String sub) {
		return Db.sqlOne("SELECT user_id FROM lti.subjects WHERE tool_id = ? AND sub = ?",
				new JsonArray().add(toolId).add(sub)).map(row -> row == null ? null : row.getString("user_id"));
	}

	static String inPlaceholders(int size) {
		final StringBuilder sb = new StringBuilder("(");
		for (int i = 0; i < size; i++) {
			sb.append(i == 0 ? "?" : ", ?");
		}
		return sb.append(")").toString();
	}
}
