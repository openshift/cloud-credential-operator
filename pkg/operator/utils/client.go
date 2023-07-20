package utils

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

type delegatingClient struct {
	reader client.Reader
	client.Client
}

func (d *delegatingClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	return d.reader.Get(ctx, key, obj, opts...)
}

func (d *delegatingClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return d.reader.List(ctx, list, opts...)
}

var _ client.Client = (*delegatingClient)(nil)

// LiveClient returns a client.Client that never uses the cache by virtue of using the APIReader() for
// all read operations.
func LiveClient(mgr manager.Manager) client.Client {
	return &delegatingClient{
		reader: mgr.GetAPIReader(),
		Client: mgr.GetClient(),
	}
}
