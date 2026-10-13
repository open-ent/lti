package fr.openent.lti.service;

import io.vertx.core.Future;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.util.List;
import java.util.UUID;

/** Liens de ressource (Deep Linking). */
public class LinkRepository {

	private static final String COLUMNS = "id, tool_id, deployment_id, context_id, target_type, target_id, type, title, " +
			"text, url, custom, created_by, created_at";

	public Future<JsonObject> find(String id) {
		return Db.sqlOne("SELECT " + COLUMNS + " FROM lti.resource_links WHERE id = ?", new JsonArray().add(id));
	}

	public Future<JsonObject> create(String toolId, String deploymentId, String contextId, String targetType,
			String targetId, JsonObject item, String userId) {
		return Db.sqlOne("INSERT INTO lti.resource_links (id, tool_id, deployment_id, context_id, target_type, target_id, " +
				"type, title, text, url, custom, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?) " +
				"RETURNING " + COLUMNS, new JsonArray()
				.add(UUID.randomUUID().toString()).add(toolId).add(deploymentId).add(contextId)
				.add(targetType).add(targetId).add(item.getString("type")).add(item.getString("title"))
				.add(item.getString("text")).add(item.getString("url"))
				.add(item.getJsonObject("custom", new JsonObject()).encode()).add(userId));
	}

	/** Liens rattachés à un objet ENT, limités aux contextes de l'utilisateur ou à ses propres liens. */
	public Future<JsonArray> listForTarget(String targetType, String targetId, String userId, List<String> contexts) {
		final JsonArray params = new JsonArray().add(targetType).add(targetId).add(userId);
		String contextFilter = "";
		if (contexts != null && !contexts.isEmpty()) {
			contextFilter = " OR l.context_id IN " + ToolRepository.inPlaceholders(contexts.size());
			contexts.forEach(params::add);
		}
		return Db.sql("SELECT l.id, l.tool_id, t.name AS tool_name, l.context_id, l.type, l.title, l.text, l.url, " +
				"l.created_at FROM lti.resource_links l JOIN lti.tools t ON t.id = l.tool_id " +
				"WHERE t.enabled = TRUE AND l.target_type = ? AND l.target_id = ? AND (l.created_by = ?" +
				contextFilter + ") ORDER BY l.created_at", params);
	}

	public Future<JsonArray> delete(String id, String userId) {
		return Db.sql("DELETE FROM lti.resource_links WHERE id = ? AND created_by = ? RETURNING id",
				new JsonArray().add(id).add(userId));
	}
}
