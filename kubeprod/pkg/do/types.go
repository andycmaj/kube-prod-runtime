/*
 * Bitnami Kubernetes Production Runtime - A collection of services that makes it
 * easy to run production workloads in Kubernetes.
 *
 * Copyright 2020 Bitnami
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package do

import (
	flag "github.com/spf13/pflag"
)

// Config required by mariadb galera
type MariaDBGaleraConfig struct {
	RootPassword        string `json:"root_password"`
	MariaBackupPassword string `json:"mariabackup_password"`
}

// Config options required by oauth2-proxy
type OauthProxyConfig struct {
	CookieSecret string `json:"cookie_secret"`
	AuthzDomain  string `json:"authz_domain"`
}

// Config options required by keycloak
type KeycloakConfig struct {
	DatabasePassword string `json:"db_password"`
	Password         string `json:"admin_password"`
	ClientID         string `json:"client_id"`
	ClientSecret     string `json:"client_secret"`
	Group            string `json:"group"`
}

type DoApiConfig struct {
	AuthToken string `json:"auth_token"`
}

// Local config required for DO platform
type DoConfig struct {
	flags *flag.FlagSet

	// TODO: Promote this to a proper (versioned) k8s Object
	DnsZone       string              `json:"dnsZone"`
	ContactEmail  string              `json:"contactEmail"`
	Keycloak      KeycloakConfig      `json:"keycloak"`
	OauthProxy    OauthProxyConfig    `json:"oauthProxy"`
	MariaDBGalera MariaDBGaleraConfig `json:"mariadbGalera"`
	DoApi         DoApiConfig         `json:"do_api"`
}
