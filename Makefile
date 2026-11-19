KEYCLOAK_URL ?= https://localhost:8443
KEYCLOAK_CA ?= $(HOME)/.config/keycloak-mcp/certs/ca.crt
ANSIBLE ?= ansible-playbook
ANSIBLE_INVENTORY ?= ansible/inventory/hosts.yml
ANSIBLE_ARGS ?=
REALM ?= lab

.PHONY: up down init plan apply policies destroy

up:
	$(ANSIBLE) -i $(ANSIBLE_INVENTORY) ansible/playbooks/site.yml $(ANSIBLE_ARGS)

down:
	$(ANSIBLE) -i $(ANSIBLE_INVENTORY) ansible/playbooks/teardown.yml $(ANSIBLE_ARGS)

init:
	terraform -chdir=terraform init -input=false

plan:
	terraform -chdir=terraform plan -input=false

apply:
	terraform -chdir=terraform apply -input=false

# CIMD client policies need typed booleans/lists. The Keycloak Terraform
# provider stores executor configuration as strings, so this declarative JSON
# is applied through the Admin API instead. The password is passed on stdin.
policies:
	@test -n "$$KEYCLOAK_ADMIN_PASSWORD" || (echo "set KEYCLOAK_ADMIN_PASSWORD" && exit 1)
	@set -e; \
	token=$$(printf '%s' "$$KEYCLOAK_ADMIN_PASSWORD" | \
	  curl -fsS --proto '=https' --cacert "$(KEYCLOAK_CA)" \
	    --data-urlencode 'password@-' --data-urlencode "username=$${KEYCLOAK_ADMIN_USER:-admin}" \
	    -d 'client_id=admin-cli&grant_type=password' \
	    "$(KEYCLOAK_URL)/realms/master/protocol/openid-connect/token" | \
	  python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'); \
	for entry in profiles:cimd-profile policies:cimd-policy; do \
	  endpoint=$${entry%%:*}; input=$${entry#*:}; \
	  printf 'Authorization: Bearer %s\n' "$$token" | \
	    curl -fsS --proto '=https' --cacert "$(KEYCLOAK_CA)" -o /dev/null -w "$$endpoint %{http_code}\n" \
	      -X PUT -H @- -H 'Content-Type: application/json' --data-binary "@realm/$$input.json" \
	      "$(KEYCLOAK_URL)/admin/realms/$(REALM)/client-policies/$$endpoint"; \
	done

destroy:
	terraform -chdir=terraform destroy -input=false
