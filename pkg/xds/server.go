package xds

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	extension "github.com/envoyproxy/go-control-plane/envoy/service/extension/v3"

	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/server/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"

	// Loading these triggers the population of protoregistry via their inits.
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/cors/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	jwt_authn "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
)

func streamOpenFunc(ctx context.Context, i int64, s string) error {
	log.Infof("streamOpenFunc %d %s", i, s)
	return nil
}

func streamClosedFunc(i int64, node *core.Node) {
	log.Infof("streamClosedFunc %d", i)
}

func streamRequestFunc(i int64, req *discovery.DiscoveryRequest) error {
	if req.ErrorDetail != nil {
		log.Errorf("%+v", req.ErrorDetail)
	}
	log.Infof("streamRequestFunc %d %s", i, req.TypeUrl)
	return nil
}

func streamResponseFunc(ctx context.Context, i int64, req *discovery.DiscoveryRequest, resp *discovery.DiscoveryResponse) {
	log.Infof("streamResponseFunc %d %s %d", i, req.TypeUrl, len(resp.Resources))
}

func deltaStreamOpenFunc(ctx context.Context, i int64, s string) error {
	log.Infof("deltaStreamOpenFunc %d %s", i, s)
	return nil
}

func deltaStreamClosedFunc(i int64, node *core.Node) {
	log.Infof("deltaStreamClosedFunc %d", i)
}

func streamDeltaRequestFunc(i int64, req *discovery.DeltaDiscoveryRequest) error {
	if req.ErrorDetail != nil {
		log.Errorf("%+v", req.ErrorDetail)
	}
	log.Infof("streamDeltaRequestFunc %d %s", i, req.TypeUrl)
	return nil
}

func streamDeltaResponseFunc(i int64, req *discovery.DeltaDiscoveryRequest, resp *discovery.DeltaDiscoveryResponse) {
	log.Infof("streamDeltaResponseFunc %d %s %d", i, req.TypeUrl, len(resp.Resources))
}

// Run entry point for Envoy XDS command line.
func Run() error {

	callbacks := server.CallbackFuncs{
		DeltaStreamOpenFunc:     deltaStreamOpenFunc,
		DeltaStreamClosedFunc:   deltaStreamClosedFunc,
		StreamDeltaRequestFunc:  streamDeltaRequestFunc,
		StreamDeltaResponseFunc: streamDeltaResponseFunc,
		StreamOpenFunc:          streamOpenFunc,
		StreamClosedFunc:        streamClosedFunc,
		StreamRequestFunc:       streamRequestFunc,
		StreamResponseFunc:      streamResponseFunc,
	}

	snapshotCache := cache.NewSnapshotCache(true, cache.IDHash{}, log)

	server := serverv3.NewServer(context.Background(), snapshotCache, callbacks)
	grpcServer := grpc.NewServer()
	reflection.Register(grpcServer)
	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", config.Port))
	if err != nil {
		log.Fatal(err)
	}

	extension.RegisterExtensionConfigDiscoveryServiceServer(grpcServer, server)
	//discovery.RegisterAggregatedDiscoveryServiceServer(grpcServer, server)

	go func() {
		if err = grpcServer.Serve(lis); err != nil {
			log.Fatal(err)
		}
	}()

	log.Infof("Listening on %d", config.Port)
	StartSnapshotting(context.Background(), 10000, snapshotCache)

	// Wait for CTRL-c shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	<-done

	grpcServer.GracefulStop()
	log.Info("Shutdown")
	return nil
}

func StartSnapshotting(ctx context.Context, intervalMS uint, snapshotCache cache.SnapshotCache) {
	go func() {
		ticker := time.NewTicker(time.Duration(intervalMS) * time.Millisecond)
		for {
			select {
			case <-ticker.C:
				snapshot, err := getSnapshot()
				if err != nil {
					log.Errorf("%+v", err)
					return
				}
				snapshotCache.SetSnapshot(ctx, "ecdsdemo", snapshot)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func getSnapshot() (*cache.Snapshot, error) {
	version := fmt.Sprintf("%d", time.Now().UnixNano())
	log.Infof("version: %s", version)

	jwt, err := anypb.New(&jwt_authn.JwtAuthentication{
		Providers: map[string]*jwt_authn.JwtProvider{
			"okta-jwt": {
				Issuer: "https://dev-94945820.okta.com/oauth2/authserver",
				Audiences: []string{
					"api://authserver",
				},
				PayloadInMetadata:    "jwt_payload",
				ForwardPayloadHeader: "x-axway-jwt-payload",
				JwksSourceSpecifier: &jwt_authn.JwtProvider_RemoteJwks{
					RemoteJwks: &jwt_authn.RemoteJwks{
						HttpUri: &core.HttpUri{
							Uri:              "https://dev-94945820.okta.com/oauth2/authserver/v1/keys",
							Timeout:          durationpb.New(time.Millisecond * 10000),
							HttpUpstreamType: &core.HttpUri_Cluster{Cluster: "jwks_cluster"},
						},
					},
				},
				FromHeaders: []*jwt_authn.JwtHeader{{Name: "Authorization", ValuePrefix: "Bearer "}},
			},
		},
	})

	if err != nil {
		return nil, err
	}

	extensions := []types.Resource{
		&core.TypedExtensionConfig{
			Name:        "envoy.filters.http.jwt_authn",
			TypedConfig: jwt,
		},
	}

	return cache.NewSnapshot(version, map[string][]types.Resource{
		resource.ExtensionConfigType: extensions,
	})
}
