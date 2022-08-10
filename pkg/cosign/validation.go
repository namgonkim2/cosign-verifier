//
// Copyright 2021 The Sigstore Authors.
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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/sigstore/pkg/fulcioroots"
	"github.com/sigstore/sigstore/pkg/signature"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	logger = ctrl.Log.WithName("validation")
)

func Valid(ctx context.Context, ref name.Reference, signer string, keys []crypto.PublicKey, opts ...ociremote.Option) ([]oci.Signature, error) {
	if len(keys) == 0 {
		// If there are no keys, then verify against the fulcio root.
		// but we don`t use it.
	}
	// We return nil if ANY key matches
	var lastErr error
	for _, k := range keys {
		verifier, err := signature.LoadVerifier(k, crypto.SHA256)
		if err != nil {
			msg := fmt.Sprintf("error creating verifier: %v", err)
			logger.Error(err, msg)
			lastErr = err
			continue
		}

		sps, err := validSignatures(ctx, ref, signer, verifier, opts...)
		if err != nil {
			msg := fmt.Sprintf("error validating signatures: %v", err)
			logger.Error(err, msg)
			lastErr = err
			continue
		}
		return sps, nil
	}
	logger.Info("No valid signatures were found.")
	return nil, lastErr
}

// For testing
var cosignVerifySignatures = cosign.VerifyImageSignatures

func validSignatures(ctx context.Context, ref name.Reference, signer string, verifier signature.Verifier, opts ...ociremote.Option) ([]oci.Signature, error) {
	fulcioRoots, err := fulcioroots.Get()
	if err != nil {
		return nil, err
	}
	sigs, _, err := cosignVerifySignatures(ctx, ref, &cosign.CheckOpts{
		RegistryClientOpts: opts,
		RootCerts:          fulcioRoots,
		SigVerifier:        verifier,
		ClaimVerifier:      cosign.SimpleClaimVerifier,
		Annotations: map[string]interface{}{
			"signer": signer,
		},
	})
	return sigs, err
}

func GetPublicKey(cfg map[string][]byte) ([]crypto.PublicKey, error) {
	keys := []crypto.PublicKey{}
	errs := []error{}

	logger.Info("Get Public key...")
	pems := parsePems(cfg["cosign.pub"])
	for _, p := range pems {
		// TODO: check header
		key, err := x509.ParsePKIXPublicKey(p.Bytes)
		if err != nil {
			errs = append(errs, err)
		} else {
			keys = append(keys, key.(crypto.PublicKey))
		}
	}
	if keys == nil {
		msg := fmt.Sprintf("malformed cosign.pub: %v", errs)
		return nil, errors.Wrap(errs[0], msg)
	}
	return keys, nil
}

func parsePems(b []byte) []*pem.Block {
	p, rest := pem.Decode(b)
	if p == nil {
		return nil
	}
	pems := []*pem.Block{p}

	if rest != nil {
		return append(pems, parsePems(rest)...)
	}
	return pems
}
