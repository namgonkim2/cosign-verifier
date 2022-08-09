package kubernetes

import (
	"context"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"strings"
)

const (
	KeyReference = "k8s://"
)

// get cosign key-pair from secret resource in k8s cluster
func GetKeyPairSecret(client *kubernetes.Clientset, ctx context.Context, k8sKeyRef string) (*v1.Secret, error) {
	namespace, name, err := parseRef(k8sKeyRef)
	if err != nil {
		return nil, err
	}

	var s *v1.Secret
	if s, err = client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{}); err != nil {
		return nil, errors.Wrap(err, "checking if secret exists")
	}

	return s, nil
}

// the reference should be formatted as <namespace>/<secret name>
func parseRef(k8sRef string) (string, string, error) {
	s := strings.Split(strings.TrimPrefix(k8sRef, KeyReference), "/")
	if len(s) != 2 {
		return "", "", errors.New("kubernetes specification should be in the format k8s://<namespace>/<secret>")
	}
	return s[0], s[1], nil
}
