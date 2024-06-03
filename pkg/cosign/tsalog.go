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
	"context"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa"
	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/sigstore/sigstore/pkg/tuf"
)

const (
	tsaLeafCertStr                = `tsa_leaf.crt.pem`
	tsaRootCertStr                = `tsa_root.crt.pem`
	tsaIntermediateCertStrPattern = `tsa_intermediate_%d.crt.pem`
)

type TSACertificates struct {
	LeafCert          *x509.Certificate
	IntermediateCerts []*x509.Certificate
	RootCert          []*x509.Certificate
}

type GetTargetStub func(name string) ([]byte, error)

func GetTufTargets(name string) ([]byte, error) {
	tufClient, _ := tuf.NewFromEnv(context.Background())
	return tufClient.GetTarget(name)
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

	if altTSACert != "" {
		raw, err = os.ReadFile(altTSACert)
	} else if certChainPath != "" {
		raw, err = os.ReadFile(certChainPath)
	} else {
		if err != nil {
			return nil, err
		}
		leafCert, err := fn(tsaLeafCertStr)
		if err != nil {
			return nil, fmt.Errorf("error fetching TSA leaf certificate: %w", err)
		}
		rootCert, err := fn(tsaRootCertStr)
		if err != nil {
			return nil, fmt.Errorf("error fetching TSA root certificate: %w", err)
		}
		var intermediates []*x509.Certificate
		for i := 0; ; i++ {
			intermediateCertStr := fmt.Sprintf(tsaIntermediateCertStrPattern, i)
			intermediateCert, err := fn(intermediateCertStr)
			if err != nil {
				break
			}
			intermediateCertParsed, err := x509.ParseCertificate(intermediateCert)
			if err != nil {
				return nil, fmt.Errorf("error parsing TSA intermediate certificate: %w", err)
			}
			intermediates = append(intermediates, intermediateCertParsed)
		}
		leafCertParsed, err := x509.ParseCertificate(leafCert)
		if err != nil {
			return nil, fmt.Errorf("error parsing TSA leaf certificate: %w", err)
		}
		rootCertParsed, err := x509.ParseCertificate(rootCert)
		if err != nil {
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

	leaves, intermediates, roots, err := tsa.SplitPEMCertificateChain(raw)
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
