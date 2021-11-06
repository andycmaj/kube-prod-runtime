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
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/bitnami/kube-prod-runtime/kubeprod/tools"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

func (conf *Config) getAwsSession() *session.Session {
	if conf.session == nil {
		conf.session = session.Must(
			session.NewSessionWithOptions(
				session.Options{
					// Load AWS SDK configuration parameters (including the AWS region)
					SharedConfigState: session.SharedConfigEnable,
					// Prompt on stdin for MFA token if required
					AssumeRoleTokenProvider: stscreds.StdinTokenProvider,
				}))
	}
	return conf.session
}

// Retrieves the identity of the caller. Among other details retrieves
// the AWS account number.
func (conf *Config) getCallerIdentity(ctx context.Context) (*sts.GetCallerIdentityOutput, error) {
	svc := sts.New(conf.getAwsSession())
	result, err := svc.GetCallerIdentityWithContext(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("Error retrieving caller identity\n%v", err)
	}
	return result, nil
}

// Creates a new hosted zone in Route 53 if required, or reuses an existing
// one that matches the fully-qualified name for the DNS zone to be used by
// BKPR.
func (conf *Config) createHostedZone(ctx context.Context) (*string, error) {
	dnsZone := conf.DNSZone
	if !strings.HasSuffix(dnsZone, ".") {
		dnsZone = dnsZone + "."
	}

	svc := route53.New(conf.getAwsSession())
	listResult, err := svc.ListHostedZonesByNameWithContext(ctx, &route53.ListHostedZonesByNameInput{
		DNSName:  aws.String(dnsZone),
		MaxItems: aws.String("1"),
	})
	if err != nil {
		return nil, fmt.Errorf("Error listing Route 53 zone named: %s: %v", dnsZone, err)
	}

	log.Debugf("Hosted zone in Route 53: %s", listResult.GoString())
	if len(listResult.HostedZones) > 0 && *listResult.HostedZones[0].Name == dnsZone {
		// Returns the "hostedzone/<ZONEID>" string
		hostedZoneID := (*listResult.HostedZones[0].Id)[1:]
		log.Warningf("Re-using exting Route 53 %s for External DNS integration: %s", hostedZoneID, dnsZone)
		return &hostedZoneID, nil
	}

	// Create the hosted zone in Route 53
	createResult, err := svc.CreateHostedZoneWithContext(ctx, &route53.CreateHostedZoneInput{
		CallerReference: aws.String(strings.ToUpper(uuid.New().String())),
		Name:            aws.String(dnsZone),
		HostedZoneConfig: &route53.HostedZoneConfig{
			Comment: aws.String("Created by BKPR installer"),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("Error creating Route 53 zone named: %s: %v", dnsZone, err)
	}
	// Returns the "hostedzone/<ZONEID>" string
	hostedZoneID := (*createResult.HostedZone.Id)[1:]
	return &hostedZoneID, nil
}

// Creates a new user policy (or reuses the existing one) in AWS to allow
// for integration between External DNS and the corresponding hosted zone
// in Route 53 zone. The user policy is named like "bbkpr-${dnsZone}".
func (conf *Config) getUserPolicy(ctx context.Context) (*string, error) {
	type StatementEntry struct {
		Effect   string
		Action   []string
		Resource string
	}

	type PolicyDocument struct {
		Version   string
		Statement []StatementEntry
	}

	// Creates (or reuses) the hosted zone in Route 53 to be used for
	// integration with External DNS
	hostedZoneID, err := conf.createHostedZone(ctx)
	if err != nil {
		return nil, err
	}

	b, err := json.Marshal(&PolicyDocument{
		Version: "2012-10-17",
		Statement: []StatementEntry{
			{
				Effect: "Allow",
				Action: []string{
					"route53:GetHostedZone",
					"route53:GetHostedZoneCount",
					"route53:ListHostedZones",
					"route53:ListHostedZonesByName",
					"route53:ListResourceRecordSets",
				},
				Resource: "*",
			},
			{
				Effect: "Allow",
				// Allows for DeleteItem, GetItem, PutItem, Scan, and UpdateItem
				Action: []string{
					"route53:ChangeResourceRecordSets",
				},
				Resource: arn.ARN{
					Partition: "aws",
					Service:   "route53",
					Resource:  *hostedZoneID,
				}.String(),
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("Error marshaling policy: %v", err)
	}

	svc := iam.New(conf.getAwsSession())
	policyName := aws.String(fmt.Sprintf("bkpr-%s", conf.DNSZone))
	result, err := svc.CreatePolicyWithContext(ctx, &iam.CreatePolicyInput{
		PolicyDocument: aws.String(string(b)),
		PolicyName:     policyName,
	})

	if err == nil {
		// Return ARN of the previously created policy object
		log.Info("Created IAM policy for External DNS integration: ", *result.Policy.Arn)
		return result.Policy.Arn, nil
	}

	// Check why the request to create the IAM policy failed...
	if aerr, ok := err.(awserr.Error); ok {
		if aerr.Code() == iam.ErrCodeEntityAlreadyExistsException {
			log.Warning("Re-using existing IAM policy for External DNS integration: ", *policyName)
			callerIdentity, err := conf.getCallerIdentity(ctx)
			if err != nil {
				return nil, err
			}
			arn := arn.ARN{
				Partition: "aws",
				Service:   "iam",
				AccountID: *callerIdentity.Account,
				Resource:  fmt.Sprintf("policy/%s", *policyName),
			}.String()
			result, err := svc.GetPolicyWithContext(ctx, &iam.GetPolicyInput{
				PolicyArn: aws.String(arn),
			})
			if err != nil {
				return nil, fmt.Errorf("Error looking up IAM policy with ARN %v: %v", arn, err)
			}
			// Store ARN of the existing policy object
			return result.Policy.Arn, nil
		}
	}

	// Unable to handle any other errors.
	return nil, fmt.Errorf("Error creating IAM policy: %v", err)
}

// Attaches the correct IAM policy to the user used for integration with
// External DNS.
func (conf *Config) attachUserPolicy(ctx context.Context) error {
	// Retrieve the ARN for the policy that limits the privileges for
	// the user to be used for External DNS integration
	policyArn, err := conf.getUserPolicy(ctx)
	if err != nil {
		return err
	}
	userName := fmt.Sprintf("bkpr-%s", conf.DNSZone)
	log.Debugf("Policy ARN: %s", *policyArn)

	svc := iam.New(conf.getAwsSession())
	_, err = svc.AttachUserPolicyWithContext(ctx, &iam.AttachUserPolicyInput{
		PolicyArn: policyArn,
		UserName:  aws.String(userName),
	})
	if err != nil {
		return fmt.Errorf("Error attaching policy %s to user %s: %v", *policyArn, userName, err)
	}
	log.Info("Attached IAM policy for External DNS integration")
	return nil
}

// Creates a new user (or reuses the existing one) in AWS to allow
// for integration between External DNS and a hosted Route53 zone.
// The user is named like "bbkpr-${dnsZone}" and will get an IAM
// policy attached to it which limits R/W to the hosted Route53 zone
// to be used by BKPR and R/O for any other zones. The IAM policy
// will be created if necessary.
func (conf *Config) createAwsUser(ctx context.Context) (*string, *string, error) {
	userName := fmt.Sprintf("bkpr-%s", conf.DNSZone)

	// Create an AWS user
	svc := iam.New(conf.getAwsSession())
	_, err := svc.CreateUserWithContext(ctx, &iam.CreateUserInput{
		UserName: aws.String(userName),
		Tags: []*iam.Tag{
			{
				Key:   aws.String("created_by"),
				Value: aws.String("bkpr"),
			},
		},
	})
	if err != nil {
		log.Warning("Re-using existing AWS user for External DNS integration: ", userName)
	} else {
		log.Infof("Created AWS user: %s", userName)
	}

	conf.attachUserPolicy(ctx)

	// Create/Add an Access Key
	ak, err := svc.CreateAccessKeyWithContext(ctx, &iam.CreateAccessKeyInput{
		UserName: aws.String(userName),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("Cannot create AWS access key for External DNS integration: %v", err)
	}
	return ak.AccessKey.AccessKeyId, ak.AccessKey.SecretAccessKey, nil
}

// Configuration for integration between External DNS and AWS.
func (conf *Config) setUpExternalDNS(ctx context.Context) error {
	log.Info("Setting up configuration for External DNS")
	flags := conf.flags

	if conf.ExternalDNS.AWSAccessKeyID == "" {
		AWSAccessKeyID, err := flags.GetString(flagAWSAccessKeyID)
		if err != nil {
			return err
		}
		conf.ExternalDNS.AWSAccessKeyID = AWSAccessKeyID
	}
	if conf.ExternalDNS.AWSSecretAccessKey == "" {
		AWSSecretAccessKey, err := flags.GetString(flagAWSSecretAccessKey)
		if err != nil {
			return err
		}
		conf.ExternalDNS.AWSSecretAccessKey = AWSSecretAccessKey
	}

	// At this point, if the AWS secret is still empty, try to create an AWS
	// access key for a user named "bkpr.${dnsZone}"
	if conf.ExternalDNS.AWSAccessKeyID == "" || conf.ExternalDNS.AWSSecretAccessKey == "" {
		awsAccessKeyID, awsSecretAccessKey, err := conf.createAwsUser(ctx)
		if err != nil {
			return err
		}
		conf.ExternalDNS.AWSAccessKeyID = *awsAccessKeyID
		conf.ExternalDNS.AWSSecretAccessKey = *awsSecretAccessKey
	}
	return nil
}

// Generate platform configuration
func (conf *Config) Generate(ctx context.Context) error {
	flags := conf.flags

	if conf.ContactEmail == "" {
		email, err := flags.GetString(flagEmail)
		if err != nil {
			return err
		}
		conf.ContactEmail = email
	}

	if conf.DNSZone == "" {
		domain, err := flags.GetString(flagDNSSuffix)
		if err != nil {
			return err
		}
		conf.DNSZone = domain
	}

	if conf.DNSZone != "" {
		//
		// External DNS setup
		//
		err := conf.setUpExternalDNS(ctx)
		if err != nil {
			return err
		}
	}

	// mariadb setup
	log.Debug("Starting mariadb galera setup")
	if conf.MariaDBGalera.RootPassword == "" {
		rand, err := tools.Base64RandBytes(24)
		if err != nil {
			return err
		}
		conf.MariaDBGalera.RootPassword = rand
	}

	if conf.MariaDBGalera.MariaBackupPassword == "" {
		rand, err := tools.Base64RandBytes(24)
		if err != nil {
			return err
		}
		conf.MariaDBGalera.MariaBackupPassword = rand
	}

	// keycloak setup
	log.Debug("Starting keycloak setup")

	if conf.Keycloak.DatabasePassword == "" {
		rand, err := tools.Base64RandBytes(24)
		if err != nil {
			return err
		}
		conf.Keycloak.DatabasePassword = rand
	}

	if conf.Keycloak.Password == "" {
		password, err := flags.GetString(flagKeycloakPassword)
		if err != nil {
			return err
		}
		conf.Keycloak.Password = password
	}

	if conf.Keycloak.ClientID == "" {
		conf.Keycloak.ClientID = "bkpr"
	}

	if conf.Keycloak.ClientSecret == "" {
		conf.Keycloak.ClientSecret = uuid.New().String()
	}

	//
	// oauth2-proxy setup
	//
	log.Debug("Starting oauth2-proxy setup")

	if conf.OauthProxy.CookieSecret == "" {
		// I Quote: cookie_secret must be 16, 24, or 32 bytes
		// to create an AES cipher when pass_access_token ==
		// true or cookie_refresh != 0
		secret, err := tools.Base64RandBytes(24)
		if err != nil {
			return err
		}
		conf.OauthProxy.CookieSecret = secret
	}

	if conf.OauthProxy.AuthzDomain == "" {
		domain, err := flags.GetString(flagAuthzDomain)
		if err != nil {
			return err
		}
		conf.OauthProxy.AuthzDomain = domain
	}

	return nil
}
