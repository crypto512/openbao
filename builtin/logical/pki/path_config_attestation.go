// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	storageAttestationConfig       = "config/attestation"
	storageAttestationEKRootsPrefix = "config/attestation/ek-roots/"
	pathConfigAttestationHelpSyn   = "Configuration of Device Attestation"
	pathConfigAttestationHelpDesc  = `
This endpoint configures global device attestation settings for ACME.

enabled=false - Whether device attestation support is enabled globally. Defaults to false.

validate_ek_certificate=false - Whether to validate Endorsement Key (EK) certificate
chains for TPM attestation by default. When enabled, the attestation statement's
certificate chain must be validated against the configured EK root certificates.

default_attestation_policies=[] - Default list of policy OIDs that should be present
in attestation certificates. These can be overridden at the role level.

allowed_attestation_formats=["tpm"] - Which attestation formats are allowed globally.
Supported formats: "tpm", "android-key", "apple", "chromeos".
`
)

type attestationConfigEntry struct {
	// Enabled controls whether device attestation is supported
	Enabled bool `json:"enabled"`
	// ValidateEKCertificate controls whether EK certificate validation is enabled by default
	ValidateEKCertificate bool `json:"validate_ek_certificate"`
	// DefaultAttestationPolicies contains default policy OIDs required in certificates
	DefaultAttestationPolicies []string `json:"default_attestation_policies"`
	// AllowedAttestationFormats lists the globally allowed attestation formats
	AllowedAttestationFormats []string `json:"allowed_attestation_formats"`
}

var defaultAttestationConfig = attestationConfigEntry{
	Enabled:                    false,
	ValidateEKCertificate:      true,
	DefaultAttestationPolicies: []string{},
	AllowedAttestationFormats:  []string{"tpm"},
}

func (sc *storageContext) getAttestationConfig() (*attestationConfigEntry, error) {
	entry, err := sc.Storage.Get(sc.Context, storageAttestationConfig)
	if err != nil {
		return nil, err
	}

	var mapping attestationConfigEntry
	if entry == nil {
		mapping = defaultAttestationConfig
		return &mapping, nil
	}

	if err := entry.DecodeJSON(&mapping); err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to decode attestation configuration: %v", err)}
	}

	return &mapping, nil
}

func (sc *storageContext) setAttestationConfig(entry *attestationConfigEntry) error {
	json, err := logical.StorageEntryJSON(storageAttestationConfig, entry)
	if err != nil {
		return fmt.Errorf("failed creating storage entry: %w", err)
	}

	if err := sc.Storage.Put(sc.Context, json); err != nil {
		return fmt.Errorf("failed writing storage entry: %w", err)
	}

	return nil
}

func pathAttestationConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/attestation",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
		},

		Fields: map[string]*framework.FieldSchema{
			"enabled": {
				Type:        framework.TypeBool,
				Description: `Whether device attestation is enabled globally. Defaults to false.`,
				Default:     false,
			},
			"validate_ek_certificate": {
				Type: framework.TypeBool,
				Description: `Whether to validate Endorsement Key (EK) certificate chains for TPM attestation by default.
When enabled, the attestation statement's certificate chain must be validated against configured EK root certificates.
Defaults to true for security. IMPORTANT: EK validation should be enabled for production use with properly
configured EK root certificates. Disabling this weakens the security of device attestation.`,
				Default: true,
			},
			"default_attestation_policies": {
				Type: framework.TypeCommaStringSlice,
				Description: `Default list of policy OIDs that should be present in attestation certificates.
These can be overridden at the role level. Format: comma-separated OIDs (e.g., "1.2.3.4,1.2.3.5").`,
				Default: []string{},
			},
			"allowed_attestation_formats": {
				Type: framework.TypeCommaStringSlice,
				Description: `Which attestation formats are allowed globally. Supported formats: "tpm", "android-key", "apple", "chromeos".
This can be further restricted at the role level.`,
				Default: []string{"tpm"},
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "attestation-configuration",
				},
				Callback: b.pathAttestationRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathAttestationWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "configure",
					OperationSuffix: "attestation",
				},
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},

		HelpSynopsis:    pathConfigAttestationHelpSyn,
		HelpDescription: pathConfigAttestationHelpDesc,
	}
}

func (b *backend) pathAttestationRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)
	config, err := sc.getAttestationConfig()
	if err != nil {
		return nil, err
	}

	return genResponseFromAttestationConfig(config), nil
}

func genResponseFromAttestationConfig(config *attestationConfigEntry) *logical.Response {
	response := &logical.Response{
		Data: map[string]interface{}{
			"enabled":                      config.Enabled,
			"validate_ek_certificate":      config.ValidateEKCertificate,
			"default_attestation_policies": config.DefaultAttestationPolicies,
			"allowed_attestation_formats":  config.AllowedAttestationFormats,
		},
	}

	return response
}

func (b *backend) pathAttestationWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)

	config, err := sc.getAttestationConfig()
	if err != nil {
		return nil, err
	}

	if enabledRaw, ok := d.GetOk("enabled"); ok {
		config.Enabled = enabledRaw.(bool)
	}

	if validateEKRaw, ok := d.GetOk("validate_ek_certificate"); ok {
		config.ValidateEKCertificate = validateEKRaw.(bool)
	}

	if policiesRaw, ok := d.GetOk("default_attestation_policies"); ok {
		config.DefaultAttestationPolicies = policiesRaw.([]string)
	}

	if formatsRaw, ok := d.GetOk("allowed_attestation_formats"); ok {
		formats := formatsRaw.([]string)

		// Validate attestation formats
		validFormats := map[string]bool{
			"tpm":         true,
			"android-key": true,
			"apple":       true,
			"chromeos":    true,
		}

		for _, format := range formats {
			if !validFormats[format] {
				return logical.ErrorResponse("invalid attestation format: %s. Valid formats are: tpm, android-key, apple, chromeos", format), nil
			}
		}

		config.AllowedAttestationFormats = formats
	}

	err = sc.setAttestationConfig(config)
	if err != nil {
		return nil, err
	}

	return genResponseFromAttestationConfig(config), nil
}
