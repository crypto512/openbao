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

// Storage path for AK CA root certificates
const akCaRootsStoragePrefix = "config/attestation/ak-ca-roots/"

// akCaRootEntry represents a stored AK CA root certificate
type akCaRootEntry struct {
	Name        string `json:"name"`
	Certificate string `json:"certificate"` // PEM-encoded certificate
}

func pathAcmeAkCaRoots(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config/acme/ak-ca-roots/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "acme",
				OperationSuffix: "ak-ca-roots",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathListAkCaRoots,
					Summary:  "List all configured AK CA root certificates",
				},
			},
			HelpSynopsis:    "List AK CA root certificates for device attestation",
			HelpDescription: "This endpoint lists all configured AK CA root certificates used to validate AIK certificates during device attestation.",
		},
		{
			Pattern: "config/acme/ak-ca-roots/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "acme",
				OperationSuffix: "ak-ca-root",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the AK CA root certificate",
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
					Callback: b.pathWriteAkCaRoot,
					Summary:  "Add or update an AK CA root certificate",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathWriteAkCaRoot,
					Summary:  "Add or update an AK CA root certificate",
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadAkCaRoot,
					Summary:  "Read an AK CA root certificate",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteAkCaRoot,
					Summary:  "Delete an AK CA root certificate",
				},
			},
			HelpSynopsis:    "Manage individual AK CA root certificates",
			HelpDescription: "This endpoint allows you to add, read, update, or delete AK CA root certificates used to validate AIK certificates during device attestation.",
		},
	}
}

// pathListAkCaRoots lists all configured AK CA root certificates
func (b *backend) pathListAkCaRoots(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, akCaRootsStoragePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list AK CA root certificates: %w", err)
	}

	return logical.ListResponse(entries), nil
}

// pathReadAkCaRoot reads a specific AK CA root certificate
func (b *backend) pathReadAkCaRoot(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	entry, err := b.getAkCaRootEntry(ctx, req.Storage, name)
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

// pathWriteAkCaRoot writes an AK CA root certificate
func (b *backend) pathWriteAkCaRoot(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
	entry := &akCaRootEntry{
		Name:        name,
		Certificate: certPEM,
	}

	jsonEntry, err := logical.StorageEntryJSON(akCaRootsStoragePrefix+name, entry)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage entry: %w", err)
	}

	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		return nil, fmt.Errorf("failed to store AK CA root certificate: %w", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name": name,
		},
	}, nil
}

// pathDeleteAkCaRoot deletes an AK CA root certificate
func (b *backend) pathDeleteAkCaRoot(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	if err := req.Storage.Delete(ctx, akCaRootsStoragePrefix+name); err != nil {
		return nil, fmt.Errorf("failed to delete AK CA root certificate: %w", err)
	}

	return nil, nil
}

// getAkCaRootEntry retrieves an AK CA root certificate entry from storage
func (b *backend) getAkCaRootEntry(ctx context.Context, s logical.Storage, name string) (*akCaRootEntry, error) {
	entry, err := s.Get(ctx, akCaRootsStoragePrefix+name)
	if err != nil {
		return nil, fmt.Errorf("failed to read AK CA root certificate: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	var result akCaRootEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, fmt.Errorf("failed to decode AK CA root certificate: %w", err)
	}

	return &result, nil
}

// loadAllAkCaRootCertificates loads all configured AK CA root certificates from storage
func loadAllAkCaRootCertificates(ctx context.Context, s logical.Storage) ([]*x509.Certificate, error) {
	names, err := s.List(ctx, akCaRootsStoragePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list AK CA root certificates: %w", err)
	}

	var certs []*x509.Certificate
	for _, name := range names {
		entry, err := s.Get(ctx, akCaRootsStoragePrefix+name)
		if err != nil {
			return nil, fmt.Errorf("failed to read AK CA root certificate %s: %w", name, err)
		}
		if entry == nil {
			continue
		}

		var akCaRoot akCaRootEntry
		if err := entry.DecodeJSON(&akCaRoot); err != nil {
			return nil, fmt.Errorf("failed to decode AK CA root certificate %s: %w", name, err)
		}

		// Parse PEM certificate
		block, _ := pem.Decode([]byte(akCaRoot.Certificate))
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
