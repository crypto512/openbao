// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Storage path for EK root certificates
const ekRootsStoragePrefix = "config/acme/ek-roots/"

// ekRootEntry represents a stored EK root certificate
type ekRootEntry struct {
	Name        string `json:"name"`
	Certificate string `json:"certificate"` // PEM-encoded certificate
}

func pathAcmeEkRoots(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config/acme/ek-roots/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "acme",
				OperationSuffix: "ek-roots",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathListEkRoots,
					Summary:  "List all configured EK root certificates",
				},
			},
			HelpSynopsis:    "List EK root certificates for device attestation",
			HelpDescription: "This endpoint lists all configured EK root certificates used to validate TPM endorsement keys during device attestation.",
		},
		{
			Pattern: "config/acme/ek-roots/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "acme",
				OperationSuffix: "ek-root",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the EK root certificate",
					Required:    true,
				},
				"certificate": {
					Type:        framework.TypeString,
					Description: "PEM-encoded X.509 certificate",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathWriteEkRoot,
					Summary:  "Add or update an EK root certificate",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathWriteEkRoot,
					Summary:  "Add or update an EK root certificate",
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadEkRoot,
					Summary:  "Read an EK root certificate",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteEkRoot,
					Summary:  "Delete an EK root certificate",
				},
			},
			HelpSynopsis:    "Manage individual EK root certificates",
			HelpDescription: "This endpoint allows you to add, read, update, or delete EK root certificates used to validate TPM endorsement keys during device attestation.",
		},
	}
}

// pathListEkRoots lists all configured EK root certificates
func (b *backend) pathListEkRoots(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, ekRootsStoragePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list EK root certificates: %w", err)
	}

	return logical.ListResponse(entries), nil
}

// pathReadEkRoot reads a specific EK root certificate
func (b *backend) pathReadEkRoot(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	entry, err := b.getEkRootEntry(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":        entry.Name,
			"certificate": entry.Certificate,
		},
	}, nil
}

// pathWriteEkRoot writes an EK root certificate
func (b *backend) pathWriteEkRoot(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	certPEM := data.Get("certificate").(string)
	if certPEM == "" {
		return logical.ErrorResponse("missing certificate"), nil
	}

	// Validate the certificate
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return logical.ErrorResponse("failed to decode PEM certificate"), nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return logical.ErrorResponse("failed to parse certificate: %v", err), nil
	}

	// Verify it's a CA certificate
	if !cert.IsCA {
		return logical.ErrorResponse("certificate must be a CA certificate"), nil
	}

	// Store the entry
	entry := &ekRootEntry{
		Name:        name,
		Certificate: certPEM,
	}

	jsonEntry, err := logical.StorageEntryJSON(ekRootsStoragePrefix+name, entry)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage entry: %w", err)
	}

	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		return nil, fmt.Errorf("failed to store EK root certificate: %w", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name": name,
		},
	}, nil
}

// pathDeleteEkRoot deletes an EK root certificate
func (b *backend) pathDeleteEkRoot(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	if err := req.Storage.Delete(ctx, ekRootsStoragePrefix+name); err != nil {
		return nil, fmt.Errorf("failed to delete EK root certificate: %w", err)
	}

	return nil, nil
}

// getEkRootEntry retrieves an EK root certificate entry from storage
func (b *backend) getEkRootEntry(ctx context.Context, s logical.Storage, name string) (*ekRootEntry, error) {
	entry, err := s.Get(ctx, ekRootsStoragePrefix+name)
	if err != nil {
		return nil, fmt.Errorf("failed to read EK root certificate: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	var result ekRootEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, fmt.Errorf("failed to decode EK root certificate: %w", err)
	}

	return &result, nil
}

// loadAllEkRootCertificates loads all configured EK root certificates from storage
func loadAllEkRootCertificates(ctx context.Context, s logical.Storage) ([]*x509.Certificate, error) {
	names, err := s.List(ctx, ekRootsStoragePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list EK root certificates: %w", err)
	}

	var certs []*x509.Certificate
	for _, name := range names {
		entry, err := s.Get(ctx, ekRootsStoragePrefix+name)
		if err != nil {
			return nil, fmt.Errorf("failed to read EK root certificate %s: %w", name, err)
		}
		if entry == nil {
			continue
		}

		var ekRoot ekRootEntry
		if err := entry.DecodeJSON(&ekRoot); err != nil {
			return nil, fmt.Errorf("failed to decode EK root certificate %s: %w", name, err)
		}

		// Parse PEM certificate
		block, _ := pem.Decode([]byte(ekRoot.Certificate))
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM certificate for %s", name)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate for %s: %w", name, err)
		}

		certs = append(certs, cert)
	}

	return certs, nil
}
