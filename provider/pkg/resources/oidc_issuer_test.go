// Copyright 2026, Pulumi Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package resources

import (
	"testing"

	"github.com/pulumi/pulumi-pulumiservice/provider/pkg/pulumiapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOidcIssuerID(t *testing.T) {
	assert.Equal(t, "my-org/issuer-123", oidcIssuerID(gcMyOrg, "issuer-123"))
}

func TestSplitOidcIssuerID(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		org, id, err := splitOidcIssuerID("my-org/issuer-123")
		require.NoError(t, err)
		assert.Equal(t, gcMyOrg, org)
		assert.Equal(t, "issuer-123", id)
	})

	t.Run("too few parts", func(t *testing.T) {
		_, _, err := splitOidcIssuerID("just-one")
		require.Error(t, err)
	})

	t.Run("too many parts", func(t *testing.T) {
		_, _, err := splitOidcIssuerID("a/b/c")
		require.Error(t, err)
	})
}

func TestOidcIssuerPolicySerialization(t *testing.T) {
	t.Parallel()

	teamName := "dream-team"
	userLogin := "testuser"
	runnerID := "runner-123"
	roleID := "role-456"
	maxExpiration := int64(3600)

	input := OidcIssuerInput{
		Organization:         "test-org",
		Name:                 "test-issuer",
		URL:                  "https://example.com",
		MaxExpirationSeconds: &maxExpiration,
		Thumbprints:          []string{"thumbprint1", "thumbprint2"},
		Policies: []AuthPolicyDefinition{
			{
				Decision:              AuthPolicyDecisionAllow,
				TokenType:             AuthPolicyTokenTypeOrganization,
				AuthorizedPermissions: []AuthPolicyPermissionLevel{AuthPolicyPermissionLevelAdmin},
				Rules: map[string]string{
					"aud": "urn:pulumi:org:test-org",
					"sub": "repo:organization/repo:*",
				},
			},
			{
				Decision:  AuthPolicyDecisionDeny,
				TokenType: AuthPolicyTokenTypePersonal,
				UserLogin: &userLogin,
				Rules: map[string]string{
					"aud": "urn:pulumi:org:test-org",
					"sub": "pulumi:deploy:org:test-org:project:test-project:*",
				},
			},
			{
				Decision:              AuthPolicyDecisionAllow,
				TokenType:             AuthPolicyTokenTypeTeam,
				TeamName:              &teamName,
				AuthorizedPermissions: []AuthPolicyPermissionLevel{AuthPolicyPermissionLevelStandard},
				Rules: map[string]string{
					"aud": "urn:pulumi:org:test-org",
					"sub": "repo:organization/repo:*",
				},
			},
			{
				Decision:  AuthPolicyDecisionAllow,
				TokenType: AuthPolicyTokenTypeDeploymentRunner,
				RunnerID:  &runnerID,
				Rules: map[string]string{
					"aud": "urn:pulumi:org:test-org",
					"sub": "repo:organization/repo:*",
				},
			},
			{
				Decision:  AuthPolicyDecisionDeny,
				TokenType: AuthPolicyTokenTypeOrganization,
				RoleID:    &roleID,
				Rules: map[string]string{
					"aud": "urn:pulumi:org:test-org",
					"sub": "repo:organization/repo:*",
					"env": "production",
				},
			},
		},
	}

	apiRequest := policiesToAPIRequest(input.Policies)
	apiPoliciesPtr := make([]*pulumiapi.AuthPolicyDefinition, len(apiRequest.Definition))
	for i := range apiRequest.Definition {
		apiPoliciesPtr[i] = &apiRequest.Definition[i]
	}

	resultPolicies := apiPoliciesToInputs(apiPoliciesPtr)
	assert.Equal(t, input.Policies, resultPolicies)
}
