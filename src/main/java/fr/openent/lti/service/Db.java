package fr.openent.lti.service;

import fr.wseduc.webutils.Either;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import org.entcore.common.neo4j.Neo4j;
import org.entcore.common.neo4j.Neo4jResult;
import org.entcore.common.sql.Sql;
import org.entcore.common.sql.SqlResult;

/** Accès PostgreSQL (mod-postgresql) et Neo4j sous forme de Future. */
public final class Db {

	private Db() {
	}

	public static Future<JsonArray> sql(String query, JsonArray params) {
		final Promise<JsonArray> promise = Promise.promise();
		Sql.getInstance().prepared(query, params, SqlResult.validResultHandler(either -> complete(promise, either)));
		return promise.future();
	}

	/** Première ligne ou null. */
	public static Future<JsonObject> sqlOne(String query, JsonArray params) {
		return sql(query, params).map(rows -> rows.isEmpty() ? null : rows.getJsonObject(0));
	}

	public static Future<JsonArray> neo4j(String query, JsonObject params) {
		final Promise<JsonArray> promise = Promise.promise();
		Neo4j.getInstance().execute(query, params, Neo4jResult.validResultHandler(either -> complete(promise, either)));
		return promise.future();
	}

	private static void complete(Promise<JsonArray> promise, Either<String, JsonArray> either) {
		if (either.isRight()) {
			promise.complete(either.right().getValue());
		} else {
			promise.fail(either.left().getValue());
		}
	}

	/** Les colonnes JSONB peuvent être renvoyées sous forme de chaîne par mod-postgresql. */
	public static JsonArray jsonArray(JsonObject row, String key) {
		final Object value = row.getValue(key);
		if (value instanceof JsonArray) {
			return (JsonArray) value;
		}
		return value instanceof String ? new JsonArray((String) value) : new JsonArray();
	}

	public static JsonObject jsonObject(JsonObject row, String key) {
		final Object value = row.getValue(key);
		if (value instanceof JsonObject) {
			return (JsonObject) value;
		}
		return value instanceof String ? new JsonObject((String) value) : null;
	}

	public static String encode(Object json) {
		if (json instanceof JsonObject) {
			return ((JsonObject) json).encode();
		}
		if (json instanceof JsonArray) {
			return ((JsonArray) json).encode();
		}
		return null;
	}
}
