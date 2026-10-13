package fr.openent.lti.service;

import io.vertx.core.Future;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/** Colonnes de notes et scores (LTI AGS 2.0), toujours bornés à (outil, contexte). */
public class AgsRepository {

	private static final String COLUMNS = "id, tool_id, context_id, resource_link_id, resource_id, tag, label, " +
			"score_maximum, start_date_time, end_date_time";

	public Future<JsonArray> list(String toolId, String contextId, String resourceLinkId, String resourceId, String tag,
			int limit, int offset) {
		final StringBuilder query = new StringBuilder("SELECT " + COLUMNS + " FROM lti.line_items WHERE tool_id = ? AND context_id = ?");
		final JsonArray params = new JsonArray().add(toolId).add(contextId);
		if (resourceLinkId != null) {
			query.append(" AND resource_link_id = ?");
			params.add(resourceLinkId);
		}
		if (resourceId != null) {
			query.append(" AND resource_id = ?");
			params.add(resourceId);
		}
		if (tag != null) {
			query.append(" AND tag = ?");
			params.add(tag);
		}
		query.append(" ORDER BY id LIMIT ? OFFSET ?");
		params.add(limit).add(offset);
		return Db.sql(query.toString(), params);
	}

	public Future<JsonObject> find(String toolId, String contextId, long id) {
		return Db.sqlOne("SELECT " + COLUMNS + " FROM lti.line_items WHERE id = ? AND tool_id = ? AND context_id = ?",
				new JsonArray().add(id).add(toolId).add(contextId));
	}

	public Future<JsonObject> findByResourceLink(String resourceLinkId) {
		return Db.sqlOne("SELECT " + COLUMNS + " FROM lti.line_items WHERE resource_link_id = ? ORDER BY id LIMIT 1",
				new JsonArray().add(resourceLinkId));
	}

	public Future<JsonObject> create(String toolId, String contextId, JsonObject item) {
		return Db.sqlOne("INSERT INTO lti.line_items (tool_id, context_id, resource_link_id, resource_id, tag, label, " +
				"score_maximum, start_date_time, end_date_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?::timestamptz, ?::timestamptz) " +
				"RETURNING " + COLUMNS, new JsonArray().add(toolId).add(contextId)
				.add(item.getString("resourceLinkId")).add(item.getString("resourceId")).add(item.getString("tag"))
				.add(item.getString("label")).add(item.getDouble("scoreMaximum"))
				.add(item.getString("startDateTime")).add(item.getString("endDateTime")));
	}

	public Future<JsonObject> update(String toolId, String contextId, long id, JsonObject item) {
		return Db.sqlOne("UPDATE lti.line_items SET resource_id = ?, tag = ?, label = ?, score_maximum = ?, " +
				"start_date_time = ?::timestamptz, end_date_time = ?::timestamptz " +
				"WHERE id = ? AND tool_id = ? AND context_id = ? RETURNING " + COLUMNS, new JsonArray()
				.add(item.getString("resourceId")).add(item.getString("tag")).add(item.getString("label"))
				.add(item.getDouble("scoreMaximum")).add(item.getString("startDateTime"))
				.add(item.getString("endDateTime")).add(id).add(toolId).add(contextId));
	}

	public Future<Boolean> delete(String toolId, String contextId, long id) {
		return Db.sql("DELETE FROM lti.line_items WHERE id = ? AND tool_id = ? AND context_id = ? RETURNING id",
				new JsonArray().add(id).add(toolId).add(contextId)).map(rows -> !rows.isEmpty());
	}

	/**
	 * Enregistre un score ; un score plus ancien que celui déjà stocké est ignoré (AGS 2.0 §3.4).
	 * @return true si le score a été pris en compte
	 */
	public Future<Boolean> upsertScore(long lineItemId, String userId, JsonObject score) {
		return Db.sql("INSERT INTO lti.scores (line_item_id, user_id, score_given, score_maximum, comment, " +
				"activity_progress, grading_progress, \"timestamp\") VALUES (?, ?, ?, ?, ?, ?, ?, ?::timestamptz) " +
				"ON CONFLICT (line_item_id, user_id) DO UPDATE SET score_given = EXCLUDED.score_given, " +
				"score_maximum = EXCLUDED.score_maximum, comment = EXCLUDED.comment, " +
				"activity_progress = EXCLUDED.activity_progress, grading_progress = EXCLUDED.grading_progress, " +
				"\"timestamp\" = EXCLUDED.\"timestamp\", updated_at = NOW() " +
				"WHERE lti.scores.\"timestamp\" < EXCLUDED.\"timestamp\" RETURNING line_item_id", new JsonArray()
				.add(lineItemId).add(userId).add(score.getDouble("scoreGiven")).add(score.getDouble("scoreMaximum"))
				.add(score.getString("comment")).add(score.getString("activityProgress"))
				.add(score.getString("gradingProgress")).add(score.getString("timestamp")))
				.map(rows -> !rows.isEmpty());
	}

	/** Résultats d'une colonne avec le pseudonyme de chaque élève pour l'outil. */
	public Future<JsonArray> results(String toolId, long lineItemId, String sub, int limit, int offset) {
		final StringBuilder query = new StringBuilder("SELECT s.score_given, s.score_maximum, s.comment, sub.sub " +
				"FROM lti.scores s JOIN lti.subjects sub ON sub.tool_id = ? AND sub.user_id = s.user_id " +
				"WHERE s.line_item_id = ?");
		final JsonArray params = new JsonArray().add(toolId).add(lineItemId);
		if (sub != null) {
			query.append(" AND sub.sub = ?");
			params.add(sub);
		}
		query.append(" ORDER BY sub.sub LIMIT ? OFFSET ?");
		params.add(limit).add(offset);
		return Db.sql(query.toString(), params);
	}
}
