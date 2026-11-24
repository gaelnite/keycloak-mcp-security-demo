#!/usr/bin/env node
// Cedar PDP for the Keycloak MCP reference server.
//
// One JSON request per line on stdin, one JSON response per line on stdout. Loads
// and validates the schema/policies/entities once, names policies by their @id
// annotation, and returns the bundle hash with every decision. Any failure is
// {ok:false}; the Python PEP fails closed.
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import {
  getCedarVersion,
  isAuthorized,
  policySetTextToParts,
  validate,
} from "@cedar-policy/cedar-wasm/nodejs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CEDAR = path.resolve(HERE, "..", "cedar");

function emit(payload) {
  process.stdout.write(JSON.stringify(payload) + "\n");
}
function fail(code, detail) {
  emit({ ok: false, error: code, detail });
  process.exit(3);
}

let schema;
let policyText;
let entitiesRaw;
try {
  schema = fs.readFileSync(path.join(CEDAR, "schema.cedarschema"), "utf8");
  policyText = fs.readFileSync(path.join(CEDAR, "policies.cedar"), "utf8");
  entitiesRaw = fs.readFileSync(path.join(CEDAR, "entities.json"), "utf8");
} catch (error) {
  fail("read_error", String(error));
}

let entities;
try {
  entities = JSON.parse(entitiesRaw);
} catch (error) {
  fail("entities_json", String(error));
}

const parsed = policySetTextToParts(policyText);
if (parsed.type !== "success") fail("policy_parse", JSON.stringify(parsed.errors));
const staticPolicies = {};
for (const policyPart of parsed.policies) {
  const match = policyPart.match(/@id\("([^"]+)"\)/);
  if (!match) fail("missing_policy_id", policyPart.slice(0, 120));
  if (staticPolicies[match[1]]) fail("duplicate_policy_id", match[1]);
  staticPolicies[match[1]] = policyPart;
}
const policies = { staticPolicies };
const validation = validate({ schema, policies });
if (validation.type !== "success" || (validation.validationErrors || []).length > 0) {
  fail("policy_validation", JSON.stringify(validation.validationErrors || validation.errors || []));
}

const bundleHash = crypto
  .createHash("sha256")
  .update(schema)
  .update("\0")
  .update(policyText)
  .update("\0")
  .update(entitiesRaw)
  .digest("hex");

const meta = {
  cedarVersion: getCedarVersion(),
  bundleHash,
  policyIds: Object.keys(staticPolicies).sort(),
};

// The runtime entity store carries the tool surface. Everything about a caller is
// supplied per request by the PEP from *verified* token claims, so a decision cannot
// depend on a principal that someone remembered to seed into entities.json.
const DYNAMIC_FACTS_KEY = new Map([
  ["KeycloakMCP::User", "user"],
  ["KeycloakMCP::Client", "client"],
]);
const REALM_RESOURCE_PREFIX = "realm:";

function isEntityUid(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    typeof value.type === "string" &&
    typeof value.id === "string"
  );
}

function realmUid(id) {
  return { type: "KeycloakMCP::Realm", id };
}

function realmResourceUid(id) {
  return { type: "KeycloakMCP::Resource", id: REALM_RESOURCE_PREFIX + id };
}

// The realm a request acts on arrives as Cedar's resource (`realm:<id>`) and is not
// guaranteed to be in the store: realms are discovered at runtime from Keycloak, while
// entities.json is generated from the tool registry. It has to exist anyway, or a
// cross-realm attempt would fail as a Cedar evaluation error instead of reaching
// kc-deny-cross-realm - and an evaluation error is a worse audit record than a denial.
function contextRealmId(request) {
  const resource = request.context && request.context.resource;
  const uid = resource && resource.__entity;
  if (
    isEntityUid(uid) &&
    uid.type === "KeycloakMCP::Resource" &&
    uid.id.startsWith(REALM_RESOURCE_PREFIX) &&
    uid.id.length > REALM_RESOURCE_PREFIX.length
  ) {
    return uid.id.slice(REALM_RESOURCE_PREFIX.length);
  }
  return undefined;
}

function requestEntities(request) {
  const factsKey = DYNAMIC_FACTS_KEY.get(request.principal && request.principal.type);
  const facts = factsKey === undefined ? undefined : request[factsKey];
  const realmIds = new Set();
  const targetRealm = contextRealmId(request);
  if (targetRealm !== undefined) realmIds.add(targetRealm);

  if (facts !== undefined) {
    if (!isEntityUid(request.principal) || typeof facts.attrs !== "object" || facts.attrs === null) {
      throw new Error("invalid dynamic principal");
    }
    // Never let a request redefine an entity the bundle already knows: a static Tool,
    // Realm or fixture principal stays exactly as the bundle defines it.
    if (entities.some((entity) => entity.uid.type === request.principal.type && entity.uid.id === request.principal.id)) {
      throw new Error("dynamic principal shadows a static entity");
    }
    // `facts.realm` is the realm the *caller* belongs to (verified `iss` on the wire),
    // which is usually - but not always - the realm being acted on.
    if (typeof facts.realm !== "string" || facts.realm === "") {
      throw new Error("dynamic principal without a realm");
    }
    realmIds.add(facts.realm);
  }

  const known = (uid) => entities.some((entity) => entity.uid.type === uid.type && entity.uid.id === uid.id);
  if (facts === undefined && realmIds.size === 0) return entities;
  const dynamic = [...entities];
  for (const id of realmIds) {
    const realm = realmUid(id);
    if (!known(realm)) dynamic.push({ uid: realm, attrs: {}, parents: [] });
    const resource = realmResourceUid(id);
    if (!known(resource)) {
      dynamic.push({ uid: resource, attrs: { kind: "realm", realm: { __entity: realm } }, parents: [] });
    }
  }
  if (facts !== undefined) {
    dynamic.push({
      uid: request.principal,
      attrs: facts.attrs,
      parents: [{ __entity: realmUid(facts.realm) }],
    });
  }
  return dynamic;
}

function authorize(request) {
  let answer;
  try {
    answer = isAuthorized({
      principal: request.principal,
      action: request.action,
      resource: request.resource,
      context: request.context || {},
      schema,
      policies,
      entities: requestEntities(request),
      validateRequest: true,
    });
  } catch (error) {
    return { ok: false, error: "pdp_error", detail: String(error) };
  }
  if (answer.type === "failure") {
    return { ok: false, error: "pdp_failure", errors: answer.errors };
  }
  return {
    ok: true,
    decision: answer.response.decision,
    determiningPolicies: answer.response.diagnostics.reason,
    errors: (answer.response.diagnostics.errors || []).map((item) => ({
      policyId: item.policyId,
      message: item.error ? item.error.message : String(item),
    })),
    warnings: answer.warnings || [],
  };
}

const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
lines.on("line", (line) => {
  if (!line.trim()) return;
  let request;
  try {
    request = JSON.parse(line);
  } catch (error) {
    emit({ ok: false, error: "bad_json", detail: String(error) });
    return;
  }
  const requestId = request.requestId === undefined ? null : request.requestId;
  if (request.op === "ping") {
    emit({ ok: true, requestId, ...meta });
    return;
  }
  if (request.op === "validate") {
    emit({ ok: true, requestId, valid: validation.type === "success", bundleHash });
    return;
  }
  if (request.op === "authorize") {
    emit({ requestId, bundleHash, cedarVersion: meta.cedarVersion, ...authorize(request) });
    return;
  }
  emit({ ok: false, requestId, error: "unknown_op" });
});
lines.on("close", () => process.exit(0));
