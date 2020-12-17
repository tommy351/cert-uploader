package main

import (
	"os"

	"github.com/tommy351/cert-uploader/internal/controller"
	"github.com/tommy351/cert-uploader/pkg/apis/certuploader/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
)

// +kubebuilder:rbac:groups="",namespace=cert-uploader,resources=configmaps,verbs=get;create;update
// +kubebuilder:rbac:groups="coordination.k8s.io",namespace=cert-uploader,resources=leases,verbs=get;create;update

func init() {
	log.SetLogger(zap.New())
}

func main() {
	scheme := runtime.NewScheme()
	sb := runtime.NewSchemeBuilder(v1alpha1.AddToScheme)

	if err := sb.AddToScheme(scheme); err != nil {
		log.Log.Error(err, "failed to register schemes")
		os.Exit(1)
	}

	mgr, err := manager.New(config.GetConfigOrDie(), manager.Options{
		Scheme:           scheme,
		LeaderElection:   true,
		LeaderElectionID: "cert-uploader-controller-lock",
	})
	if err != nil {
		log.Log.Error(err, "unable to set up overall controller manager")
		os.Exit(1)
	}

	reconciler := &controller.Reconciler{
		Client: mgr.GetClient(),
	}

	if err := reconciler.SetupWithManager(mgr); err != nil {
		log.Log.Error(err, "failed to setup reconciler")
		os.Exit(1)
	}

	if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
		log.Log.Error(err, "failed to start manager")
		os.Exit(1)
	}
}
