package fr.openent.lti.core;

/** Constantes LTI 1.3 / LTI Advantage (noms de claims, types de message, scopes). */
public final class Lti13 {

	private Lti13() {
	}

	public static final String VERSION = "1.3.0";

	private static final String CLAIM = "https://purl.imsglobal.org/spec/lti/claim/";
	public static final String CLAIM_MESSAGE_TYPE = CLAIM + "message_type";
	public static final String CLAIM_VERSION = CLAIM + "version";
	public static final String CLAIM_DEPLOYMENT_ID = CLAIM + "deployment_id";
	public static final String CLAIM_TARGET_LINK_URI = CLAIM + "target_link_uri";
	public static final String CLAIM_RESOURCE_LINK = CLAIM + "resource_link";
	public static final String CLAIM_ROLES = CLAIM + "roles";
	public static final String CLAIM_CONTEXT = CLAIM + "context";
	public static final String CLAIM_TOOL_PLATFORM = CLAIM + "tool_platform";
	public static final String CLAIM_LAUNCH_PRESENTATION = CLAIM + "launch_presentation";
	public static final String CLAIM_CUSTOM = CLAIM + "custom";
	public static final String CLAIM_ROLE_SCOPE_MENTOR = CLAIM + "role_scope_mentor";

	public static final String CLAIM_AGS_ENDPOINT = "https://purl.imsglobal.org/spec/lti-ags/claim/endpoint";
	public static final String CLAIM_NRPS = "https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice";

	private static final String DL = "https://purl.imsglobal.org/spec/lti-dl/claim/";
	public static final String CLAIM_DL_SETTINGS = DL + "deep_linking_settings";
	public static final String CLAIM_DL_CONTENT_ITEMS = DL + "content_items";
	public static final String CLAIM_DL_DATA = DL + "data";
	public static final String CLAIM_DL_MSG = DL + "msg";
	public static final String CLAIM_DL_ERRORMSG = DL + "errormsg";

	public static final String MSG_RESOURCE_LINK = "LtiResourceLinkRequest";
	public static final String MSG_DEEP_LINKING = "LtiDeepLinkingRequest";
	public static final String MSG_DEEP_LINKING_RESPONSE = "LtiDeepLinkingResponse";

	public static final String CONTEXT_TYPE_COURSE_SECTION = "http://purl.imsglobal.org/vocab/lis/v2/course#CourseSection";

	public static final String SCOPE_LINEITEM = "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem";
	public static final String SCOPE_LINEITEM_READONLY = "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly";
	public static final String SCOPE_RESULT_READONLY = "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly";
	public static final String SCOPE_SCORE = "https://purl.imsglobal.org/spec/lti-ags/scope/score";
	public static final String SCOPE_NRPS = "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly";

	public static final String CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

	public static final String MEDIA_LINEITEM = "application/vnd.ims.lis.v2.lineitem+json";
	public static final String MEDIA_LINEITEM_CONTAINER = "application/vnd.ims.lis.v2.lineitemcontainer+json";
	public static final String MEDIA_RESULT_CONTAINER = "application/vnd.ims.lis.v2.resultcontainer+json";
	public static final String MEDIA_SCORE = "application/vnd.ims.lis.v1.score+json";
	public static final String MEDIA_MEMBERSHIP_CONTAINER = "application/vnd.ims.lti-nrps.v2.membershipcontainer+json";
}
