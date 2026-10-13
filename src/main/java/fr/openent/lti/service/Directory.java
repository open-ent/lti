package fr.openent.lti.service;

import io.vertx.core.Future;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/** Lecture de l'annuaire ENT (Neo4j) : contextes LTI = classes ou groupes. */
public class Directory {

	private static final String MEMBER_RETURN = "RETURN DISTINCT u.id AS id, head(u.profiles) AS profile, " +
			"u.firstName AS firstName, u.lastName AS lastName, u.displayName AS displayName, u.email AS email";

	/** Classe ou groupe : { id, name } ou null. */
	public Future<JsonObject> context(String contextId) {
		final String query =
				"MATCH (c:Class {id: {id}}) RETURN c.id AS id, c.name AS name " +
				"UNION MATCH (g:Group {id: {id}}) RETURN g.id AS id, coalesce(g.displayName, g.name) AS name";
		return Db.neo4j(query, new JsonObject().put("id", contextId))
				.map(rows -> rows.isEmpty() ? null : rows.getJsonObject(0));
	}

	/** Membres d'une classe (via ses groupes de profil) ou d'un groupe. */
	public Future<JsonArray> members(String contextId) {
		final String query =
				"MATCH (c:Class {id: {id}})<-[:DEPENDS]-(:ProfileGroup)<-[:IN]-(u:User) " + MEMBER_RETURN +
				" UNION MATCH (g:Group {id: {id}})<-[:IN]-(u:User) " + MEMBER_RETURN;
		return Db.neo4j(query, new JsonObject().put("id", contextId));
	}

	public Future<Boolean> isMember(String contextId, String userId) {
		final String query =
				"MATCH (c:Class {id: {id}})<-[:DEPENDS]-(:ProfileGroup)<-[:IN]-(u:User {id: {userId}}) RETURN u.id AS id " +
				"UNION MATCH (g:Group {id: {id}})<-[:IN]-(u:User {id: {userId}}) RETURN u.id AS id";
		return Db.neo4j(query, new JsonObject().put("id", contextId).put("userId", userId))
				.map(rows -> !rows.isEmpty());
	}

	public static JsonArray page(JsonArray rows, int offset, int limit) {
		final JsonArray out = new JsonArray();
		for (int i = offset; i < rows.size() && i < offset + limit; i++) {
			out.add(rows.getValue(i));
		}
		return out;
	}
}
