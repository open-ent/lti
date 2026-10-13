CREATE SCHEMA IF NOT EXISTS lti;

CREATE TABLE lti.scripts (
	filename VARCHAR(255) NOT NULL PRIMARY KEY,
	passed TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Outils LTI enregistrés ; id = client_id attribué par la plateforme.
CREATE TABLE lti.tools (
	id VARCHAR(36) NOT NULL PRIMARY KEY,
	name VARCHAR(255) NOT NULL,
	description TEXT,
	icon_url TEXT,
	oidc_initiation_url TEXT NOT NULL,
	target_link_uri TEXT NOT NULL,
	redirect_uris JSONB NOT NULL DEFAULT '[]',
	deep_linking_url TEXT,
	jwks_url TEXT,
	public_jwk JSONB,
	scopes JSONB NOT NULL DEFAULT '[]',
	custom JSONB NOT NULL DEFAULT '{}',
	share_name BOOLEAN NOT NULL DEFAULT FALSE,
	share_email BOOLEAN NOT NULL DEFAULT FALSE,
	document_target VARCHAR(16) NOT NULL DEFAULT 'window',
	subject_salt VARCHAR(64) NOT NULL,
	enabled BOOLEAN NOT NULL DEFAULT TRUE,
	created_at TIMESTAMP NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
	CONSTRAINT tools_key_check CHECK (jwks_url IS NOT NULL OR public_jwk IS NOT NULL)
);

-- Un déploiement = activation d'un outil pour une structure (deployment_id LTI).
CREATE TABLE lti.deployments (
	id VARCHAR(36) NOT NULL PRIMARY KEY,
	tool_id VARCHAR(36) NOT NULL REFERENCES lti.tools(id) ON DELETE CASCADE,
	structure_id VARCHAR(36) NOT NULL,
	created_by VARCHAR(36),
	created_at TIMESTAMP NOT NULL DEFAULT NOW(),
	CONSTRAINT deployments_tool_structure_unique UNIQUE (tool_id, structure_id)
);
CREATE INDEX deployments_structure_idx ON lti.deployments(structure_id);

-- Contextes (classes / groupes) dans lesquels un outil a été lancé : seuls ceux-ci sont exposés via AGS / NRPS.
CREATE TABLE lti.contexts (
	tool_id VARCHAR(36) NOT NULL REFERENCES lti.tools(id) ON DELETE CASCADE,
	context_id VARCHAR(36) NOT NULL,
	deployment_id VARCHAR(36) NOT NULL REFERENCES lti.deployments(id) ON DELETE CASCADE,
	first_launch_at TIMESTAMP NOT NULL DEFAULT NOW(),
	PRIMARY KEY (tool_id, context_id)
);

-- Correspondance identifiant pseudonyme LTI (sub) ↔ utilisateur ENT, par outil.
CREATE TABLE lti.subjects (
	tool_id VARCHAR(36) NOT NULL REFERENCES lti.tools(id) ON DELETE CASCADE,
	sub VARCHAR(64) NOT NULL,
	user_id VARCHAR(36) NOT NULL,
	PRIMARY KEY (tool_id, sub)
);
CREATE INDEX subjects_user_idx ON lti.subjects(tool_id, user_id);

-- Liens de ressource créés par Deep Linking (ou placements explicites).
CREATE TABLE lti.resource_links (
	id VARCHAR(36) NOT NULL PRIMARY KEY,
	tool_id VARCHAR(36) NOT NULL REFERENCES lti.tools(id) ON DELETE CASCADE,
	deployment_id VARCHAR(36) NOT NULL REFERENCES lti.deployments(id) ON DELETE CASCADE,
	context_id VARCHAR(36),
	target_type VARCHAR(64),
	target_id VARCHAR(255),
	type VARCHAR(32) NOT NULL DEFAULT 'ltiResourceLink',
	title VARCHAR(255),
	text TEXT,
	url TEXT,
	custom JSONB NOT NULL DEFAULT '{}',
	created_by VARCHAR(36),
	created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX resource_links_target_idx ON lti.resource_links(target_type, target_id);

-- AGS : colonnes de notes.
CREATE TABLE lti.line_items (
	id BIGSERIAL PRIMARY KEY,
	tool_id VARCHAR(36) NOT NULL REFERENCES lti.tools(id) ON DELETE CASCADE,
	context_id VARCHAR(36) NOT NULL,
	resource_link_id VARCHAR(36) REFERENCES lti.resource_links(id) ON DELETE SET NULL,
	resource_id VARCHAR(255),
	tag VARCHAR(255),
	label VARCHAR(255) NOT NULL,
	score_maximum NUMERIC NOT NULL CHECK (score_maximum > 0),
	start_date_time TIMESTAMPTZ,
	end_date_time TIMESTAMPTZ,
	created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX line_items_context_idx ON lti.line_items(tool_id, context_id);

-- AGS : dernier score connu par élève et par colonne.
CREATE TABLE lti.scores (
	line_item_id BIGINT NOT NULL REFERENCES lti.line_items(id) ON DELETE CASCADE,
	user_id VARCHAR(36) NOT NULL,
	score_given NUMERIC,
	score_maximum NUMERIC,
	comment TEXT,
	activity_progress VARCHAR(32) NOT NULL,
	grading_progress VARCHAR(32) NOT NULL,
	"timestamp" TIMESTAMPTZ NOT NULL,
	updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
	PRIMARY KEY (line_item_id, user_id)
);
