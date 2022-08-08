package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"go.uber.org/zap/zapcore"
	"io/ioutil"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"strings"
	"time"

	"github.com/dlorenc/cosigned/pkg/cosigned"
	"github.com/pkg/errors"
	zaplogfmt "github.com/sykesm/zap-logfmt"
	uzap "go.uber.org/zap"
	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
)

type CosignConfig struct {
	Registry     string `yaml:"registry"`
	Image        string `yaml:"image"`
	Tag          string `yaml:"tag"`
	Signer       string `yaml:"signer"`
	SecretKeyRef string `yaml:"secretKeyRef"`
}

const KeyReference = "k8s://"

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
	kubeConfig := "/home/namgon/.kube/config"
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfig)
	if err != nil {
		panic(err.Error())
	}
	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	// Read secret for cosign key
	logger.Info("Looking for cosign key secret...")
	namespace, name, err := parseRef(cosignConfig.SecretKeyRef)
	if err != nil {
		panic(err.Error())
	}
	secret, err := clientSet.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		panic(err.Error())
	}
	if secret == nil {
		logger.Error(errors.New("Empty"), "No keys configured")
		return
	}
	keys := cosigned.Keys(secret.Data)
	logger.Info("got keys", "cosign.pub", keys)
	checkImg := fmt.Sprintf("%s/%s:%s", cosignConfig.Registry, cosignConfig.Image, cosignConfig.Tag)
	if !valid(context.TODO(), checkImg, keys) {
		logger.Error(errors.New("Invalid"), "invalid signatures")
	}
}

// the reference should be formatted as <namespace>/<secret name>
func parseRef(k8sRef string) (string, string, error) {
	s := strings.Split(strings.TrimPrefix(k8sRef, KeyReference), "/")
	if len(s) != 2 {
		return "", "", errors.New("kubernetes specification should be in the format k8s://<namespace>/<secret>")
	}
	return s[0], s[1], nil
}

func valid(ctx context.Context, img string, keys []*ecdsa.PublicKey) bool {
	for _, k := range keys {
		sps, err := cosigned.Signatures(ctx, img, k)
		if err != nil {
			logger.Error(err, "checking signatures", "image", img)
			return false
		}
		if len(sps) > 0 {
			logger.Info("valid signatures", "image", img, "key", k)
			fmt.Println(sps)
			return true
		}
	}
	return false
}
