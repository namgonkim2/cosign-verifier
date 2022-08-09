package kubernetes

import (
	"github.com/pkg/errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func GetClient() (*kubernetes.Clientset, error) {
	kubeConfig := "/home/namgon/.kube/config"
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfig)
	if err != nil {
		return nil, errors.Wrap(err, "Build k8s Config Errors")
	}
	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.Wrap(err, "New Client Set Errors")
	}

	return clientSet, nil
}
