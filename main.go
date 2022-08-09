package main

import (
	"context"
	"crypto"
	"fmt"
	cosigns "github.com/cosign-verifier/pkg/cosign"
	"github.com/cosign-verifier/pkg/kubernetes"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
	"go.uber.org/zap/zapcore"
	"io/ioutil"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"time"

	zaplogfmt "github.com/sykesm/zap-logfmt"
	uzap "go.uber.org/zap"
	"gopkg.in/yaml.v3"
	ctrl "sigs.k8s.io/controller-runtime"
)

type CosignConfig struct {
	Registry     string `yaml:"registry"`
	Image        string `yaml:"image"`
	Tag          string `yaml:"tag"`
	Signer       string `yaml:"signer"`
	SecretKeyRef string `yaml:"secretKeyRef"`
}

var (
	cosignConfig CosignConfig
	logger       = ctrl.Log.WithName("main")
)

func main() {
	configLog := uzap.NewProductionEncoderConfig()
	configLog.EncodeTime = func(ts time.Time, encoder zapcore.PrimitiveArrayEncoder) {
		encoder.AppendString(ts.UTC().Local().Format(time.RFC822))
	}
	logfmtEncoder := zaplogfmt.NewEncoder(configLog)
	ctrl.SetLogger(zap.New(zap.UseDevMode(true), zap.Encoder(logfmtEncoder)))
	// Read yaml File about cosign verify
	ymlFile, err := ioutil.ReadFile("cosignConfig.yaml")
	if err != nil {
		panic(err.Error())
	}
	err = yaml.Unmarshal(ymlFile, &cosignConfig)
	if err != nil {
		panic(err.Error())
	}
	// Read k8s my clusters ...
	logger.Info("Looking for kubernetes...")
	clientSet, err := kubernetes.GetClient()
	if err != nil {
		panic(err)
	}
	// Read secret for cosign key
	logger.Info("Looking for cosign key secret...")
	secret, err := kubernetes.GetKeyPairSecret(clientSet, context.TODO(), cosignConfig.SecretKeyRef)
	if err != nil {
		panic(err)
	}
	// Get Public Key from Secret
	keys, err := cosigns.GetPublicKey(secret.Data)
	if err != nil {
		panic(err)
	}
	logger.Info("got keys", "cosign.pub", keys)
	// Valid Image
	img := fmt.Sprintf("%s/%s:%s", cosignConfig.Registry, cosignConfig.Image, cosignConfig.Tag)
	imgRef, err := name.ParseReference(img)
	if err != nil {
		panic(err)
	}
	if !valid(context.TODO(), imgRef, cosignConfig.Signer, keys) {
		logger.Error(errors.New("Invalid"), "invalid signatures")
	}
}

func valid(ctx context.Context, imgRef name.Reference, signer string, keys []crypto.PublicKey) bool {
	for _, k := range keys {
		sps, err := cosigns.Valid(ctx, imgRef, signer, keys)
		if err != nil {
			logger.Error(err, "checking signatures", "image", imgRef)
			return false
		}
		if len(sps) > 0 {
			logger.Info("valid signatures", "image", imgRef, "key", k)
			fmt.Println(sps)
			return true
		}
	}
	return false
}
