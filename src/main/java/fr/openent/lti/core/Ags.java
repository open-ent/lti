package fr.openent.lti.core;

import io.vertx.core.json.JsonObject;

import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.List;

/** Validation et sérialisation LTI Assignment and Grade Services 2.0. */
public final class Ags {

	public static final List<String> ACTIVITY_PROGRESS =
			Arrays.asList("Initialized", "Started", "InProgress", "Submitted", "Completed");
	public static final List<String> GRADING_PROGRESS =
			Arrays.asList("FullyGraded", "Pending", "PendingManual", "Failed", "NotReady");

	private Ags() {
	}

	/** Valide un lineItem reçu (création / mise à jour) et renvoie sa forme normalisée. */
	public static JsonObject validateLineItem(JsonObject body) throws LtiException {
		if (body == null) {
			throw new LtiException("invalid.lineitem");
		}
		final String label = body.getString("label");
		if (label == null || label.trim().isEmpty() || label.length() > 255) {
			throw new LtiException("invalid.lineitem.label");
		}
		final Object max = body.getValue("scoreMaximum");
		if (!(max instanceof Number) || ((Number) max).doubleValue() <= 0) {
			throw new LtiException("invalid.lineitem.scoreMaximum");
		}
		return new JsonObject()
				.put("label", label.trim())
				.put("scoreMaximum", ((Number) max).doubleValue())
				.put("resourceId", body.getString("resourceId"))
				.put("tag", body.getString("tag"))
				.put("resourceLinkId", body.getString("resourceLinkId"))
				.put("startDateTime", optionalDate(body, "startDateTime"))
				.put("endDateTime", optionalDate(body, "endDateTime"));
	}

	/** Valide un score (POST …/scores). */
	public static JsonObject validateScore(JsonObject body) throws LtiException {
		if (body == null) {
			throw new LtiException("invalid.score");
		}
		final String userId = body.getString("userId");
		if (userId == null || userId.isEmpty()) {
			throw new LtiException("invalid.score.userId");
		}
		final String timestamp = body.getString("timestamp");
		if (timestamp == null || parseDate(timestamp) == null) {
			throw new LtiException("invalid.score.timestamp");
		}
		final String activity = body.getString("activityProgress");
		final String grading = body.getString("gradingProgress");
		if (!ACTIVITY_PROGRESS.contains(activity) || !GRADING_PROGRESS.contains(grading)) {
			throw new LtiException("invalid.score.progress");
		}
		final Object given = body.getValue("scoreGiven");
		final Object max = body.getValue("scoreMaximum");
		final JsonObject score = new JsonObject()
				.put("userId", userId)
				.put("timestamp", timestamp)
				.put("activityProgress", activity)
				.put("gradingProgress", grading)
				.put("comment", body.getString("comment"));
		if (given != null) {
			if (!(given instanceof Number) || ((Number) given).doubleValue() < 0
					|| !(max instanceof Number) || ((Number) max).doubleValue() <= 0) {
				throw new LtiException("invalid.score.value");
			}
			score.put("scoreGiven", ((Number) given).doubleValue());
			score.put("scoreMaximum", ((Number) max).doubleValue());
		}
		return score;
	}

	/** Note ramenée au barème du lineItem (null si pas de note). */
	public static Double normalized(JsonObject score, double lineItemMaximum) {
		final Double given = score.getDouble("scoreGiven");
		final Double max = score.getDouble("scoreMaximum");
		if (given == null || max == null || max <= 0) {
			return null;
		}
		return given / max * lineItemMaximum;
	}

	public static JsonObject lineItemJson(JsonObject row, String lineItemUrl) {
		final JsonObject json = new JsonObject()
				.put("id", lineItemUrl)
				.put("label", row.getString("label"))
				.put("scoreMaximum", toDouble(row.getValue("score_maximum")));
		putIfPresent(json, "resourceId", row.getString("resource_id"));
		putIfPresent(json, "tag", row.getString("tag"));
		putIfPresent(json, "resourceLinkId", row.getString("resource_link_id"));
		putIfPresent(json, "startDateTime", row.getString("start_date_time"));
		putIfPresent(json, "endDateTime", row.getString("end_date_time"));
		return json;
	}

	public static JsonObject resultJson(JsonObject row, String lineItemUrl, String ltiUserId) {
		final JsonObject json = new JsonObject()
				.put("id", lineItemUrl + "/results/" + ltiUserId)
				.put("scoreOf", lineItemUrl)
				.put("userId", ltiUserId);
		final Double given = toDouble(row.getValue("score_given"));
		if (given != null) {
			json.put("resultScore", given);
			json.put("resultMaximum", toDouble(row.getValue("score_maximum")));
		}
		putIfPresent(json, "comment", row.getString("comment"));
		return json;
	}

	static OffsetDateTime parseDate(String value) {
		try {
			return OffsetDateTime.parse(value);
		} catch (DateTimeParseException e) {
			return null;
		}
	}

	private static String optionalDate(JsonObject body, String key) throws LtiException {
		final String value = body.getString(key);
		if (value != null && parseDate(value) == null) {
			throw new LtiException("invalid.lineitem." + key);
		}
		return value;
	}

	static Double toDouble(Object o) {
		if (o instanceof Number) {
			return ((Number) o).doubleValue();
		}
		if (o instanceof String) {
			try {
				return Double.valueOf((String) o);
			} catch (NumberFormatException e) {
				return null;
			}
		}
		return null;
	}

	private static void putIfPresent(JsonObject o, String key, String value) {
		if (value != null) {
			o.put(key, value);
		}
	}
}
