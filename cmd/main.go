package main

import (
	"os"

	"github.com/tommy351/cert-uploader/internal/controller"
	"github.com/tommy351/cert-uploader/pkg/apis/certuploader/v1alpha1"
	"go.uber.org/zap/zapcore"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
)

// +kubebuilder:rbac:groups="",namespace=cert-uploader,resources=configmaps,verbs=get;create;update
// +kubebuilder:rbac:groups="coordination.k8s.io",namespace=cert-uploader,resources=leases,verbs=get;create;update

// nolint: gochecknoinits
func init() {
	log.SetLogger(zap.New(func(opts *zap.Options) {
		if !opts.Development {
			zap.JSONEncoder(func(ec *zapcore.EncoderConfig) {
				ec.EncodeTime = zapcore.ISO8601TimeEncoder
				ec.TimeKey = "time"
			})(opts)
		}
	}))
}

func main() {
	scheme := runtime.NewScheme()
	sb := runtime.NewSchemeBuilder(
		corev1.AddToScheme,
		v1alpha1.AddToScheme,
	)

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

	cur := &controller.CertificateUploadReconciler{
		Client:        mgr.GetClient(),
		EventRecorder: mgr.GetEventRecorderFor("cert-uploader"),
	}

	if err := cur.SetupWithManager(mgr); err != nil {
		log.Log.Error(err, "failed to setup reconciler")
		os.Exit(1)
	}

	sr := &controller.SecretReconciler{
		Client:                      mgr.GetClient(),
		CertificateUploadReconciler: cur,
	}

	if err := sr.SetupWithManager(mgr); err != nil {
		log.Log.Error(err, "failed to setup reconciler")
		os.Exit(1)
	}

	if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
		log.Log.Error(err, "failed to start manager")
		os.Exit(1)
	}
}
