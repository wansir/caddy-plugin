package informer

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/informers/rbac/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const EnvKubeConfig = "KUBECONFIG"

func loadConfig() (*rest.Config, error) {
	configFile := os.Getenv(EnvKubeConfig)
	var kubeConfig *rest.Config
	if len(configFile) > 0 {
		kubeConfig, err := clientcmd.BuildConfigFromFlags("", configFile)
		if err != nil {
			return nil, fmt.Errorf("kubeconfig provided in environment variable %s could not be read: %v", EnvKubeConfig, err)
		} else {
			return kubeConfig, nil
		}
	}

	kubeConfig, err := rest.InClusterConfig()

	if err != nil {
		return nil, err
	} else {
		return kubeConfig, nil
	}
}

// ClusterRoleBindingInformer Shared Informer
var ClusterRoleBindingInformer v1.ClusterRoleBindingInformer

// ClusterRoleInformer Shared Informer
var ClusterRoleInformer v1.ClusterRoleInformer

// RoleBindingInformer Shared Informer
var RoleBindingInformer v1.RoleBindingInformer

// RoleInformer Shared Informer
var RoleInformer v1.RoleInformer

// Start thread
func Start() error {

	kubeConfig, err := loadConfig()

	if err != nil {
		return err
	}

	k8s, err := kubernetes.NewForConfig(kubeConfig)

	factory := informers.NewSharedInformerFactory(k8s, time.Second*30)

	ClusterRoleBindingInformer = factory.Rbac().V1().ClusterRoleBindings()
	ClusterRoleInformer = factory.Rbac().V1().ClusterRoles()
	RoleBindingInformer = factory.Rbac().V1().RoleBindings()
	RoleInformer = factory.Rbac().V1().Roles()

	stop := make(chan struct{})
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, []os.Signal{os.Interrupt, syscall.SIGTERM}...)

	go func() {
		<-ch
		close(stop)
		<-ch
	}()

	go ClusterRoleBindingInformer.Informer().Run(stop)
	go ClusterRoleInformer.Informer().Run(stop)
	go RoleBindingInformer.Informer().Run(stop)
	go RoleInformer.Informer().Run(stop)

	return nil
}
