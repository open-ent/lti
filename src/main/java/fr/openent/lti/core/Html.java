package fr.openent.lti.core;

import java.util.Map;

/** Pages HTML minimales : formulaire auto-soumis (form_post OIDC / Deep Linking) et messages. */
public final class Html {

	private Html() {
	}

	public static String autoPostForm(String action, Map<String, String> fields) {
		final StringBuilder sb = new StringBuilder(512)
				.append("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>LTI</title></head>")
				.append("<body onload=\"document.forms[0].submit()\">")
				.append("<form method=\"post\" action=\"").append(escape(action)).append("\">");
		for (Map.Entry<String, String> field : fields.entrySet()) {
			if (field.getValue() != null) {
				sb.append("<input type=\"hidden\" name=\"").append(escape(field.getKey()))
						.append("\" value=\"").append(escape(field.getValue())).append("\">");
			}
		}
		return sb.append("<noscript><button type=\"submit\">Continuer</button></noscript></form></body></html>")
				.toString();
	}

	public static String message(String title, String text) {
		return "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>" + escape(title) + "</title></head>"
				+ "<body><h1>" + escape(title) + "</h1><p>" + escape(text) + "</p></body></html>";
	}

	public static String escape(String s) {
		if (s == null) {
			return "";
		}
		final StringBuilder sb = new StringBuilder(s.length());
		for (char c : s.toCharArray()) {
			switch (c) {
				case '&': sb.append("&amp;"); break;
				case '<': sb.append("&lt;"); break;
				case '>': sb.append("&gt;"); break;
				case '"': sb.append("&quot;"); break;
				case '\'': sb.append("&#39;"); break;
				default: sb.append(c);
			}
		}
		return sb.toString();
	}
}
