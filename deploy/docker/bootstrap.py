"""Create the isolated demo's first-install inputs in Docker-managed volumes."""

import fcntl
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from desktop_oauth import DESKTOP_CLIENT_ID, DESKTOP_REDIRECT
from delegation import ADMIN_SCOPE, admin_audience_for, spiffe_subject
from tool_registry import CAPABILITIES, LOCALE_FIXTURE_ID, LOCALES, USERS_READ

ROOT = Path("/install")
SOURCE = Path(__file__).resolve().parent
TRUST_DOMAIN = "mcp.demo"
SPIFFE_ID = f"spiffe://{TRUST_DOMAIN}/workload/keycloak-mcp-headless"
CLIENT_ID = "mcp-workload"
SCOPE = "keycloak.extensions.read"
WORKLOAD_UID = 10001
DELEGATE_UID = 10003
OPERATOR_UID = 10004
SVID_TTL = 40

# Each runtime receives only its own artifacts. Public trust files are separate.
LAYOUT = {
    "edge": (101, 101, 0o700, ("edge.crt", "edge.key", "nginx.conf")),
    "trust": (0, 0, 0o755, ("edge-ca.pem", "node-id")),
    "db-secret": (999, 999, 0o700, ("password", "application-password")),
    "postgres": (999, 999, 0o700, ()),
    "keycloak": (1000, 1000, 0o700, ("db-password", "lab-realm.json", "bundle-ca.pem")),
    "spire": (1000, 1000, 0o700, ("server.conf", "node-ca.crt", "server-ca.crt", "server-ca.key", "bundle.crt", "bundle.key")),
    "spire-data": (1000, 1000, 0o700, ()),
    "spire-control": (1000, 1000, 0o700, ()),
    "agent": (0, 0, 0o700, ("agent.conf", "node.crt", "node.key", "server-ca.crt")),
    "agent-data": (0, 0, 0o700, ()),
    "workload": (0, WORKLOAD_UID, 0o750, ()),
}


def origin():
    port = os.environ.get("DEMO_PORT", "49443")
    if not port.isascii() or not port.isdecimal() or not 1024 <= int(port) <= 65535 or str(int(port)) != port:
        raise ValueError("KC_MCP_DEMO_PORT must be a port from 1024 to 65535 without leading zeros")
    if port == "8800" or (port == "8801" and os.environ.get("DEMO_PROFILE") == "delegated"):
        raise ValueError("The HTTPS port overlaps an internal listener")
    return f"https://localhost:{port}"


def certificate(name, *, signer=None, tls=False):
    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    signing_key, issuer = (signer[0], signer[1].subject) if signer else (key, subject)
    authority = signer is None
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=730 if authority else 365))
        .add_extension(x509.BasicConstraints(ca=authority, path_length=1 if authority else None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=authority,
            crl_sign=authority, encipher_only=None, decipher_only=None,
        ), critical=True)
    )
    if tls:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    return key, builder.sign(signing_key, hashes.SHA256())


def chain_pem(certificate):
    return certificate.public_bytes(serialization.Encoding.PEM)


def key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def realm_definition(base, *, desktop_passwords=None, delegated=False):
    realm = {
        "realm": "lab",
        "enabled": True,
        "sslRequired": "all",
        "registrationAllowed": False,
        "accessTokenLifespan": 120,
        "identityProviders": [{
            "alias": "demo-spire",
            "providerId": "spiffe",
            "enabled": True,
            "hideOnLogin": True,
            "config": {
                "trustDomain": f"spiffe://{TRUST_DOMAIN}",
                "bundleEndpoint": "https://spire-server:8443/",
                "allowedClockSkew": "0",
            },
        }],
        "clientScopes": [{
            "name": "mcp-resource",
            "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "false"},
            "protocolMappers": [{
                "name": "MCP resource audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {"included.custom.audience": base + "/mcp", "access.token.claim": "true"},
            }],
        }, {
            "name": SCOPE,
            "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "true"},
        }],
        "clients": [{
            "clientId": CLIENT_ID,
            "enabled": True,
            "protocol": "openid-connect",
            "publicClient": False,
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "implicitFlowEnabled": False,
            "serviceAccountsEnabled": True,
            "fullScopeAllowed": False,
            "clientAuthenticatorType": "federated-jwt",
            "attributes": {"jwt.credential.issuer": "demo-spire", "jwt.credential.sub": SPIFFE_ID},
            "defaultClientScopes": ["mcp-resource"],
            "optionalClientScopes": [SCOPE],
        }],
    }
    if desktop_passwords is not None:
        configure_desktop(realm, base, desktop_passwords)
    if delegated:
        configure_exchange(realm, base)
    return realm


def configure_desktop(realm, base, passwords):
    resource = base + "/mcp"
    caps = tuple(CAPABILITIES.values())
    roles = [cap.role for cap in caps]
    realm.update(
        internationalizationEnabled=True, supportedLocales=list(LOCALES), defaultLocale="en",
        revokeRefreshToken=True, refreshTokenMaxReuse=0, ssoSessionIdleTimeout=300, ssoSessionMaxLifespan=900,
        clientSessionIdleTimeout=300, clientSessionMaxLifespan=900, defaultOptionalClientScopes=[],
    )
    realm["roles"] = {"realm": [{"name": role} for role in roles]}
    realm["scopeMappings"] = [{"clientScope": "mcp-entitlements", "roles": roles}]
    realm["clientScopes"].append({
        "name": "offline_access",
        "protocol": "openid-connect",
        "attributes": {"include.in.openid.provider.metadata": "false"},
    })
    realm["clientScopes"].append({
        "name": "mcp-entitlements",
        "protocol": "openid-connect",
        "attributes": {"include.in.token.scope": "false", "display.on.consent.screen": "false"},
        "protocolMappers": [{
            "name": "MCP entitlement roles",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-realm-role-mapper",
            "config": {
                "claim.name": "mcp_roles", "multivalued": "true", "jsonType.label": "String",
                "access.token.claim": "true", "id.token.claim": "false",
            },
        }],
    })
    for cap in caps:
        realm["scopeMappings"].append({"clientScope": cap.scope, "roles": [cap.role]})
        realm["clientScopes"].append({
            "name": cap.scope,
            "protocol": "openid-connect",
            "attributes": {
                "include.in.token.scope": "true", "display.on.consent.screen": "true", "consent.screen.text": cap.label,
            },
            "protocolMappers": [{
                "name": "Capability audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    "included.custom.audience": cap.requester_audience(resource),
                    "access.token.claim": "true", "id.token.claim": "false",
                },
            }],
        })
    realm["clients"].append({
        "clientId": DESKTOP_CLIENT_ID,
        "name": "Codex demo desktop",
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": True,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "implicitFlowEnabled": False,
        "serviceAccountsEnabled": False,
        "fullScopeAllowed": False,
        "consentRequired": True,
        "redirectUris": [DESKTOP_REDIRECT],
        "attributes": {"pkce.code.challenge.method": "S256", "exclude.issuer.from.auth.response": "false"},
        "defaultClientScopes": ["mcp-resource", "mcp-entitlements"],
        "optionalClientScopes": [cap.scope for cap in caps],
        "protocolMappers": [{
            "name": "Verified user subject",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-sub-mapper",
            "config": {"access.token.claim": "true", "id.token.claim": "true"},
        }],
    })
    groups = {
        "demo-helpdesk": ([USERS_READ.role], "view-users"),
        "demo-realm-admin": (roles, "realm-admin"),
    }
    realm["groups"] = [
        {"name": name, "realmRoles": roles, "clientRoles": {"realm-management": [admin_role]}}
        for name, (roles, admin_role) in groups.items()
    ]
    realm["users"] = [
        {
            "username": name, "firstName": "Demo", "lastName": "Fixture", "email": f"{name}@example.invalid",
            "enabled": True, "emailVerified": True, "groups": [f"/{name}"],
            "credentials": [{"type": "password", "value": password, "temporary": False}],
        }
        for name, password in passwords.items()
    ]
    realm["users"].append({
        "id": LOCALE_FIXTURE_ID, "username": "demo-locale-target", "enabled": False,
        "attributes": {"locale": ["en"]},
    })


def configure_exchange(realm, base):
    resource = base + "/mcp"
    admin_url = admin_audience_for(base + "/realms/lab", "lab")
    mapping = []
    realm["clientScopeMappings"] = {"realm-management": mapping}
    realm.update(adminEventsEnabled=True, adminEventsDetailsEnabled=False)
    confidential = {
        "protocol": "openid-connect", "enabled": True, "publicClient": False, "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False, "implicitFlowEnabled": False, "serviceAccountsEnabled": False,
        "fullScopeAllowed": False,
    }
    realm["clients"].append({**confidential, "clientId": admin_url, "defaultClientScopes": [], "optionalClientScopes": []})
    realm["clientScopes"].append({
        "name": ADMIN_SCOPE, "protocol": "openid-connect",
        "attributes": {"include.in.token.scope": "true", "include.in.openid.provider.metadata": "false"},
        "protocolMappers": [{
            "name": "Private Admin API audience", "protocol": "openid-connect",
            "protocolMapper": "oidc-admin-api-audience-mapper",
            "config": {"access.token.claim": "true", "id.token.claim": "false"},
        }],
    })
    for cap in CAPABILITIES.values():
        requester = cap.requester_audience(resource)
        mapping.append({"client": requester, "roles": [cap.admin_role]})
        realm["clients"].append({
            **confidential,
            "clientId": requester,
            "clientAuthenticatorType": "federated-jwt",
            "attributes": {
                "jwt.credential.issuer": "demo-spire", "jwt.credential.sub": spiffe_subject(TRUST_DOMAIN, cap),
                "standard.token.exchange.enabled": "true", "access.token.lifespan": "45",
            },
            "defaultClientScopes": [ADMIN_SCOPE],
            "optionalClientScopes": [cap.scope],
            "protocolMappers": [{
                "name": "Delegated subject", "protocol": "openid-connect", "protocolMapper": "oidc-sub-mapper",
                "config": {"access.token.claim": "true", "id.token.claim": "false"},
            }, {
                "name": "Limited Admin roles", "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-client-role-mapper",
                "config": {
                    "claim.name": "resource_access.realm-management.roles", "multivalued": "true", "jsonType.label": "String",
                    "usermodel.clientRoleMapping.clientId": "realm-management", "access.token.claim": "true", "id.token.claim": "false",
                },
            }],
        })


def write_file(path, body, mode, uid=0, gid=0):
    temporary = path.with_name("." + path.name + ".pending")
    with temporary.open("wb") as output:
        output.write(body)
        os.fchmod(output.fileno(), mode)
        os.fchown(output.fileno(), uid, gid)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)
    directory = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def generated_files(base, *, interactive=False, delegated=False):
    edge_ca = certificate("Keycloak MCP demo HTTPS CA")
    edge_key, edge_cert = certificate("localhost", signer=edge_ca, tls=True)
    bundle_ca = certificate("Keycloak MCP demo bundle HTTPS CA")
    bundle_key, bundle_cert = certificate("spire-server", signer=bundle_ca, tls=True)
    node_ca = certificate("Keycloak MCP demo node CA")
    node_key, node_cert = certificate("headless demo node", signer=node_ca)
    server_key, server_ca = certificate("Keycloak MCP demo SPIRE root")
    node_id = f"spiffe://{TRUST_DOMAIN}/spire/agent/x509pop/{node_cert.fingerprint(hashes.SHA1()).hex()}"
    db_password = secrets.token_urlsafe(36).encode()

    desktop_passwords = None
    if interactive:
        desktop_passwords = {name: secrets.token_urlsafe(32) for name in ("demo-helpdesk", "demo-realm-admin")}
    private_listener = (SOURCE / "private-admin.conf").read_text() if delegated else ""
    edge_config = (SOURCE / "edge.conf").read_text().replace("@PRIVATE_ADMIN@", private_listener)
    files = {
        "edge": {
            "edge.crt": chain_pem(edge_cert),
            "edge.key": key_pem(edge_key),
            "nginx.conf": edge_config.replace("@PORT@", base.rsplit(":", 1)[1]).encode(),
        },
        "trust": {"edge-ca.pem": chain_pem(edge_ca[1]), "node-id": node_id.encode()},
        "db-secret": {"password": secrets.token_urlsafe(36).encode(), "application-password": db_password},
        "keycloak": {
            "db-password": db_password,
            "lab-realm.json": json.dumps(realm_definition(base, desktop_passwords=desktop_passwords, delegated=delegated), indent=2).encode(),
            "bundle-ca.pem": chain_pem(bundle_ca[1]),
        },
        "spire": {
            "server.conf": (SOURCE / "server.conf").read_bytes(),
            "node-ca.crt": chain_pem(node_ca[1]),
            "server-ca.crt": chain_pem(server_ca), "server-ca.key": key_pem(server_key),
            "bundle.crt": chain_pem(bundle_cert), "bundle.key": key_pem(bundle_key),
        },
        "agent": {
            "agent.conf": (SOURCE / "agent.conf").read_bytes(),
            "node.crt": chain_pem(node_cert), "node.key": key_pem(node_key),
            "server-ca.crt": chain_pem(server_ca),
        },
    }
    if desktop_passwords is not None:
        files["desktop-fixtures"] = {"passwords.json": json.dumps(desktop_passwords).encode()}
    if delegated:
        approval = Ed25519PrivateKey.generate()
        files["approval-operator"] = {"signer.key": key_pem(approval)}
        files["delegate"] = {
            "approval.pub": approval.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            "spire-agent": Path("/opt/demo/bin/spire-agent").read_bytes(),
        }
    return files


def install(base):
    profile = os.environ.get("DEMO_PROFILE", "headless")
    if profile not in {"headless", "interactive", "delegated"}:
        raise ValueError("Unsupported demo profile")
    interactive = profile != "headless"
    delegated = profile == "delegated"
    stamp = f"{base}\n{profile}" if interactive else base
    layout = LAYOUT.copy()
    if interactive:
        layout["desktop-fixtures"] = (10002, 10002, 0o700, ("passwords.json",))
    if delegated:
        layout["approval-operator"] = (OPERATOR_UID, OPERATOR_UID, 0o700, ("signer.key",))
        layout["delegate"] = (0, 0, 0o755, ("approval.pub", "spire-agent"))
        layout["approval-state"] = (DELEGATE_UID, WORKLOAD_UID, 0o700, ())
    state = ROOT / "state"
    state.chmod(0o700)
    marker = state / "origin"
    with (state / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if marker.exists():
            if marker.read_text() != stamp:
                raise RuntimeError("Demo origin or profile differs from the installed project. Use the original settings or a new project.")
            for directory, (_, _, _, files) in layout.items():
                if not all((ROOT / directory / filename).is_file() for filename in files):
                    raise RuntimeError(f"Installation input volume {directory} is incomplete. Restore it from a consistent backup.")
            print("Existing demo installation verified")
            return
        if any((ROOT / "postgres").iterdir()) or any((ROOT / "spire-data").iterdir()):
            raise RuntimeError("Persistent service data already exists without its installation marker. Restore the matched inputs.")
        config = generated_files(base, interactive=interactive, delegated=delegated)
        for directory, (uid, gid, mode, files) in layout.items():
            path = ROOT / directory
            path.chmod(mode)
            os.chown(path, uid, gid)
            for filename in files:
                mode = 0o444 if directory == "trust" else 0o400
                if directory == "delegate":
                    mode = 0o555 if filename == "spire-agent" else 0o444
                write_file(path / filename, config[directory][filename], mode, uid, gid)
        write_file(marker, stamp.encode(), 0o400)
        print("Generated demo PKI, database credential and realm import")


if __name__ == "__main__":
    os.umask(0o077)
    install(origin())
