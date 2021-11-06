/*
 * Bitnami Kubernetes Production Runtime - A collection of services that makes it
 * easy to run production workloads in Kubernetes.
 *
 * Copyright 2019 Bitnami
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

package eks

import (
	"os"

	"github.com/spf13/cobra"

	kubeprodcmd "github.com/bitnami/kube-prod-runtime/kubeprod/cmd"
)

const (
	flagEmail              = "email"
	flagDNSSuffix          = "dns-zone"
	flagAWSAccessKeyID     = "access-key-id"
	flagAWSSecretAccessKey = "secret-access-key"
	flagAuthzDomain        = "authz-domain"
	flagKeycloakPassword   = "keycloak-password"
	flagKeycloakGroup      = "keycloak-group"
)

var eksCmd = &cobra.Command{
	Use:   "eks",
	Short: "Install Bitnami Production Runtime for EKS",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := kubeprodcmd.NewInstallSubcommand(cmd, "eks", &Config{flags: cmd.Flags()})
		if err != nil {
			return err
		}

		return c.Run(cmd.OutOrStdout())
	},
}

func init() {
	kubeprodcmd.InstallCmd.AddCommand(eksCmd)

	eksCmd.PersistentFlags().String(flagEmail, os.Getenv("EMAIL"), "Contact email for cluster admin")
	eksCmd.PersistentFlags().String(flagDNSSuffix, "", "External DNS zone for public endpoints")
	eksCmd.PersistentFlags().String(flagAWSAccessKeyID, "", "Access key ID for External DNS integration")
	eksCmd.PersistentFlags().String(flagAWSSecretAccessKey, "", "Secret access key for External DNS integration")
	eksCmd.PersistentFlags().String(flagAuthzDomain, "", "Restrict authorized users to this Google email domain")
	eksCmd.PersistentFlags().String(flagKeycloakGroup, "", "Restrict authorized users to this Keycloak group")
	eksCmd.PersistentFlags().String(flagKeycloakPassword, "", "Password for Keycloak admin user")
	eksCmd.MarkPersistentFlagRequired(flagAuthzDomain)
	eksCmd.MarkPersistentFlagRequired(flagKeycloakGroup)
	eksCmd.MarkPersistentFlagRequired(flagKeycloakPassword)
}
