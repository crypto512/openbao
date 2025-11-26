// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"
)

// OIDs for permanent identifier and hardware module name
var (
	// OID 1.3.6.1.5.5.7.8.3 - id-on-permanentIdentifier (RFC 4043)
	oidPermanentIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3}
	// OID 1.3.6.1.5.5.7.8.4 - id-on-hardwareModuleName (RFC 4108)
	oidHardwareModuleName = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 4}
)

// PermanentIdentifier represents a permanent identifier per RFC 4043
type PermanentIdentifier struct {
	IdentifierValue string
	Assigner        string // Optional
}

// HardwareModuleName represents a hardware module name per RFC 4108
type HardwareModuleName struct {
	HWType       asn1.ObjectIdentifier
	HWSerialNum  []byte
}

// AddPermanentIdentifierToTemplate adds a permanent identifier to a certificate template
// It adds the identifier to both Subject DN serialNumber and SAN otherName extension
func AddPermanentIdentifierToTemplate(template *x509.Certificate, identifier string) error {
	// Add to Subject DN serialNumber field
	template.Subject.SerialNumber = identifier

	// Add to SAN as otherName extension
	// Note: Go's x509 package doesn't directly support custom otherName types in SAN,
	// so we need to manually construct the extension
	permanentIDExtension, err := encodePermanentIdentifierExtension(identifier)
	if err != nil {
		return fmt.Errorf("failed to encode permanent identifier extension: %w", err)
	}

	// Add the extension to extra extensions
	// Note: This is a simplified approach - in production, this should properly
	// merge with existing SAN extensions
	template.ExtraExtensions = append(template.ExtraExtensions, permanentIDExtension)

	return nil
}

// encodePermanentIdentifierExtension creates a SAN extension with permanent identifier
func encodePermanentIdentifierExtension(identifier string) (pkix.Extension, error) {
	// Construct permanentIdentifier as a SEQUENCE
	// PermanentIdentifier ::= SEQUENCE {
	//   identifierValue  UTF8String,
	//   assigner         OBJECT IDENTIFIER OPTIONAL
	// }
	permanentID := struct {
		IdentifierValue string `asn1:"utf8"`
	}{
		IdentifierValue: identifier,
	}

	permanentIDBytes, err := asn1.Marshal(permanentID)
	if err != nil {
		return pkix.Extension{}, err
	}

	// Construct otherName
	// OtherName ::= SEQUENCE {
	//   type-id    OBJECT IDENTIFIER,
	//   value      [0] EXPLICIT ANY DEFINED BY type-id
	// }
	otherName := struct {
		TypeID asn1.ObjectIdentifier
		Value  asn1.RawValue `asn1:"tag:0,explicit"`
	}{
		TypeID: oidPermanentIdentifier,
		Value: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      permanentIDBytes,
		},
	}

	otherNameBytes, err := asn1.Marshal(otherName)
	if err != nil {
		return pkix.Extension{}, err
	}

	// Construct GeneralName as a SEQUENCE OF
	generalNames := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      otherNameBytes,
	}

	generalNamesBytes, err := asn1.Marshal(generalNames)
	if err != nil {
		return pkix.Extension{}, err
	}

	// SAN extension OID: 2.5.29.17
	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}

	return pkix.Extension{
		Id:       sanOID,
		Critical: false,
		Value:    generalNamesBytes,
	}, nil
}

// AddHardwareModuleNameToTemplate adds a hardware module name to a certificate template
func AddHardwareModuleNameToTemplate(template *x509.Certificate, hwType asn1.ObjectIdentifier, hwSerial []byte) error {
	// Create the hardware module name extension
	hwModuleExtension, err := encodeHardwareModuleNameExtension(hwType, hwSerial)
	if err != nil {
		return fmt.Errorf("failed to encode hardware module name extension: %w", err)
	}

	// Add the extension to extra extensions
	template.ExtraExtensions = append(template.ExtraExtensions, hwModuleExtension)

	return nil
}

// encodeHardwareModuleNameExtension creates a SAN extension with hardware module name
func encodeHardwareModuleNameExtension(hwType asn1.ObjectIdentifier, hwSerial []byte) (pkix.Extension, error) {
	// Construct HardwareModuleName as a SEQUENCE
	// HardwareModuleName ::= SEQUENCE {
	//   hwType       OBJECT IDENTIFIER,
	//   hwSerialNum  OCTET STRING
	// }
	hwModule := struct {
		HWType      asn1.ObjectIdentifier
		HWSerialNum []byte
	}{
		HWType:      hwType,
		HWSerialNum: hwSerial,
	}

	hwModuleBytes, err := asn1.Marshal(hwModule)
	if err != nil {
		return pkix.Extension{}, err
	}

	// Construct otherName
	// OtherName ::= SEQUENCE {
	//   type-id    OBJECT IDENTIFIER,
	//   value      [0] EXPLICIT ANY DEFINED BY type-id
	// }
	otherName := struct {
		TypeID asn1.ObjectIdentifier
		Value  asn1.RawValue `asn1:"tag:0,explicit"`
	}{
		TypeID: oidHardwareModuleName,
		Value: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      hwModuleBytes,
		},
	}

	otherNameBytes, err := asn1.Marshal(otherName)
	if err != nil {
		return pkix.Extension{}, err
	}

	// Construct GeneralName as a SEQUENCE OF
	generalNames := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      otherNameBytes,
	}

	generalNamesBytes, err := asn1.Marshal(generalNames)
	if err != nil {
		return pkix.Extension{}, err
	}

	// SAN extension OID: 2.5.29.17
	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}

	return pkix.Extension{
		Id:       sanOID,
		Critical: false,
		Value:    generalNamesBytes,
	}, nil
}

// URNPermanentIdentifierPrefix is the URI prefix for permanent identifiers in SAN URIs
// This format aligns with RFC 4043 concepts but uses URI SAN instead of otherName
const URNPermanentIdentifierPrefix = "urn:permanent-identifier:"

// ParsePermanentIdentifierFromCert extracts the permanent identifier from a certificate.
// This searches in the following order:
//  1. Subject DN serialNumber field
//  2. SAN otherName with permanentIdentifier OID (1.3.6.1.5.5.7.8.3) per RFC 4043
//  3. SAN URI with "urn:permanent-identifier:" prefix
//
// The URI SAN approach is particularly useful for device attestation where the
// permanent identifier needs to be easily extractable and match a pre-registered value.
func ParsePermanentIdentifierFromCert(cert *x509.Certificate) (string, error) {
	// First try Subject DN serialNumber
	if cert.Subject.SerialNumber != "" {
		return cert.Subject.SerialNumber, nil
	}

	// Parse SAN extension for otherName with permanent identifier OID
	// OID 2.5.29.17 is subjectAltName
	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(sanOID) {
			permanentID, err := parsePermanentIdentifierFromSAN(ext.Value)
			if err == nil && permanentID != "" {
				return permanentID, nil
			}
		}
	}

	// Check URI SANs for permanent-identifier URN format
	// This format is used by device attestation LAK certificates
	for _, uri := range cert.URIs {
		if uri != nil {
			uriStr := uri.String()
			if strings.HasPrefix(uriStr, URNPermanentIdentifierPrefix) {
				return strings.TrimPrefix(uriStr, URNPermanentIdentifierPrefix), nil
			}
		}
	}

	return "", fmt.Errorf("no permanent identifier found in certificate")
}

// parsePermanentIdentifierFromSAN extracts permanent identifier from SAN extension value
func parsePermanentIdentifierFromSAN(sanValue []byte) (string, error) {
	// SAN extension is a SEQUENCE OF GeneralName
	var generalNames asn1.RawValue
	if _, err := asn1.Unmarshal(sanValue, &generalNames); err != nil {
		return "", err
	}

	// Parse each GeneralName
	rest := generalNames.Bytes
	for len(rest) > 0 {
		var rawValue asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &rawValue)
		if err != nil {
			return "", err
		}

		// otherName is tagged [0]
		// Per RFC 5280 Section 4.2.1.6:
		// otherName [0] OtherName
		if rawValue.Tag == 0 && rawValue.Class == asn1.ClassContextSpecific {
			permanentID, err := parseOtherNameForPermanentIdentifier(rawValue.Bytes)
			if err == nil && permanentID != "" {
				return permanentID, nil
			}
		}
	}

	return "", fmt.Errorf("no permanent identifier found in SAN extension")
}

// parseOtherNameForPermanentIdentifier parses an otherName structure for permanent identifier
func parseOtherNameForPermanentIdentifier(otherNameBytes []byte) (string, error) {
	// OtherName ::= SEQUENCE {
	//   type-id    OBJECT IDENTIFIER,
	//   value      [0] EXPLICIT ANY DEFINED BY type-id
	// }
	var otherName struct {
		TypeID asn1.ObjectIdentifier
		Value  asn1.RawValue `asn1:"tag:0,explicit"`
	}

	if _, err := asn1.Unmarshal(otherNameBytes, &otherName); err != nil {
		return "", err
	}

	// Check if this is a permanent identifier (OID 1.3.6.1.5.5.7.8.3)
	if !otherName.TypeID.Equal(oidPermanentIdentifier) {
		return "", fmt.Errorf("not a permanent identifier OID")
	}

	// Parse the permanent identifier value
	// PermanentIdentifier ::= SEQUENCE {
	//   identifierValue  UTF8String,
	//   assigner         OBJECT IDENTIFIER OPTIONAL
	// }
	var permanentID struct {
		IdentifierValue string `asn1:"utf8"`
		Assigner        asn1.ObjectIdentifier `asn1:"optional"`
	}

	if _, err := asn1.Unmarshal(otherName.Value.Bytes, &permanentID); err != nil {
		return "", err
	}

	return permanentID.IdentifierValue, nil
}

// ParseHardwareModuleNameFromCert extracts the hardware module name from a certificate
// This searches the SAN extension for hardware module name otherName
func ParseHardwareModuleNameFromCert(cert *x509.Certificate) (string, error) {
	// Parse SAN extension for otherName with hardware module name OID
	// OID 2.5.29.17 is subjectAltName
	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(sanOID) {
			hwModuleName, err := parseHardwareModuleNameFromSAN(ext.Value)
			if err == nil && hwModuleName != "" {
				return hwModuleName, nil
			}
		}
	}

	return "", fmt.Errorf("no hardware module name found in certificate")
}

// parseHardwareModuleNameFromSAN extracts hardware module name from SAN extension value
func parseHardwareModuleNameFromSAN(sanValue []byte) (string, error) {
	// SAN extension is a SEQUENCE OF GeneralName
	var generalNames asn1.RawValue
	if _, err := asn1.Unmarshal(sanValue, &generalNames); err != nil {
		return "", err
	}

	// Parse each GeneralName
	rest := generalNames.Bytes
	for len(rest) > 0 {
		var rawValue asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &rawValue)
		if err != nil {
			return "", err
		}

		// otherName is tagged [0]
		if rawValue.Tag == 0 && rawValue.Class == asn1.ClassContextSpecific {
			hwModuleName, err := parseOtherNameForHardwareModuleName(rawValue.Bytes)
			if err == nil && hwModuleName != "" {
				return hwModuleName, nil
			}
		}
	}

	return "", fmt.Errorf("no hardware module name found in SAN extension")
}

// parseOtherNameForHardwareModuleName parses an otherName structure for hardware module name
func parseOtherNameForHardwareModuleName(otherNameBytes []byte) (string, error) {
	// OtherName ::= SEQUENCE {
	//   type-id    OBJECT IDENTIFIER,
	//   value      [0] EXPLICIT ANY DEFINED BY type-id
	// }
	var otherName struct {
		TypeID asn1.ObjectIdentifier
		Value  asn1.RawValue `asn1:"tag:0,explicit"`
	}

	if _, err := asn1.Unmarshal(otherNameBytes, &otherName); err != nil {
		return "", err
	}

	// Check if this is a hardware module name (OID 1.3.6.1.5.5.7.8.4)
	if !otherName.TypeID.Equal(oidHardwareModuleName) {
		return "", fmt.Errorf("not a hardware module name OID")
	}

	// Parse the hardware module name value
	// HardwareModuleName ::= SEQUENCE {
	//   hwType       OBJECT IDENTIFIER,
	//   hwSerialNum  OCTET STRING
	// }
	var hwModule struct {
		HWType      asn1.ObjectIdentifier
		HWSerialNum []byte
	}

	if _, err := asn1.Unmarshal(otherName.Value.Bytes, &hwModule); err != nil {
		return "", err
	}

	// Return hardware module name as "hwType:hwSerialNum" format
	// Convert serial number bytes to hex string for readability
	serialHex := fmt.Sprintf("%x", hwModule.HWSerialNum)
	return fmt.Sprintf("%s:%s", hwModule.HWType.String(), serialHex), nil
}
