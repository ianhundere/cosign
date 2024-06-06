// Copyright 2024 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cosign

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/tuf"
)

const (
	TsaLeafCertStr                = `tsa_leaf.crt.pem`
	TsaRootCertStr                = `tsa_root.crt.pem`
	TsaIntermediateCertStrPattern = `tsa_intermediate_%d.crt.pem`
)

type TSACertificates struct {
	LeafCert          *x509.Certificate
	IntermediateCerts []*x509.Certificate
	RootCert          []*x509.Certificate
}

type GetTargetStub func(ctx context.Context, usage tuf.UsageKind, names []string) ([]*x509.Certificate, error)

func GetTufTargets(ctx context.Context, usage tuf.UsageKind, names []string) ([]*x509.Certificate, error) {
	tufClient, err := tuf.NewFromEnv(ctx)
	if err != nil {
		return nil, fmt.Errorf("error creating TUF client: %w", err)
	}
	var allCerts []*x509.Certificate
	targets, err := tufClient.GetTargetsByMeta(usage, names)
	if err != nil {
		return nil, fmt.Errorf("error fetching targets by metadata with usage %v: %w", usage, err)
	}
	for _, target := range targets {
		certs, _, _, err := splitPEMCertificateChain(target.Target)
		if err != nil {
			return nil, fmt.Errorf("error splitting PEM certificate chain for target: %w", err)
		}
		allCerts = append(allCerts, certs...)
	}
	return allCerts, nil
}

// GetTSACerts retrieves trusted TSA certificates from the embedded or cached
// TUF root. If expired, makes a network call to retrieve the updated targets.
// By default, the certificates come from TUF, but you can override this for test
// purposes by using an env variable `SIGSTORE_TSA_CERTIFICATE_FILE` or a file path
// specified in `TSACertChainPath`. If using an alternate, the file should be in PEM format.
func GetTSACerts(ctx context.Context, certChainPath string, fn GetTargetStub) (*TSACertificates, error) {
	altTSACert := env.Getenv(env.VariableSigstoreTSACertificateFile)

	var raw []byte
	var err error

	switch {
	case altTSACert != "":
		raw, err = os.ReadFile(altTSACert)
	case certChainPath != "":
		raw, err = os.ReadFile(certChainPath)
	default:
		leafCert, err := fn(ctx, 0, []string{TsaLeafCertStr})
		if err != nil {
			return nil, fmt.Errorf("error fetching TSA leaf certificate: %w", err)
		}
		rootCert, err := fn(ctx, 0, []string{TsaRootCertStr})
		if err != nil {
			return nil, fmt.Errorf("error fetching TSA root certificate: %w", err)
		}
		var intermediates []*x509.Certificate
		for i := 0; ; i++ {
			intermediateCertStr := fmt.Sprintf(TsaIntermediateCertStrPattern, i)
			intermediateCert, err := fn(ctx, 0, []string{intermediateCertStr})
			if err != nil {
				break
			}
			intermediateCertParsed := intermediateCert[0]
			if intermediateCertParsed == nil {
				return nil, fmt.Errorf("error parsing TSA intermediate certificate: %w", err)
			}
			intermediates = append(intermediates, intermediateCertParsed)
		}
		leafCertParsed := leafCert[0]
		if leafCertParsed == nil {
			return nil, fmt.Errorf("error parsing TSA leaf certificate: %w", err)
		}
		rootCertParsed := rootCert[0]
		if rootCertParsed == nil {
			return nil, fmt.Errorf("error parsing TSA root certificate: %w", err)
		}
		return &TSACertificates{
			LeafCert:          leafCertParsed,
			IntermediateCerts: intermediates,
			RootCert:          []*x509.Certificate{rootCertParsed},
		}, nil
	}

	if err != nil {
		return nil, fmt.Errorf("error reading TSA certificate file: %w", err)
	}

	leaves, intermediates, roots, err := splitPEMCertificateChain(raw)
	if err != nil {
		return nil, fmt.Errorf("error splitting TSA certificates: %w", err)
	}

	if len(leaves) > 1 {
		return nil, fmt.Errorf("TSA certificate chain must contain at most one TSA certificate")
	}

	return &TSACertificates{
		LeafCert:          leaves[0],
		IntermediateCerts: intermediates,
		RootCert:          roots,
	}, nil
}

// splitPEMCertificateChain returns a list of leaf (non-CA) certificates, a certificate pool for
// intermediate CA certificates, and a certificate pool for root CA certificates
func splitPEMCertificateChain(pem []byte) (leaves, intermediates, roots []*x509.Certificate, err error) {
	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(pem)
	if err != nil {
		return nil, nil, nil, err
	}

	for _, cert := range certs {
		if !cert.IsCA {
			leaves = append(leaves, cert)
		} else {
			// root certificates are self-signed
			if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
				roots = append(roots, cert)
			} else {
				intermediates = append(intermediates, cert)
			}
		}
	}

	return leaves, intermediates, roots, nil
}