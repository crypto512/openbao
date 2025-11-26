module github.com/openbao/openbao/deviceattestpoc/client

go 1.25

require (
	github.com/fxamacker/cbor/v2 v2.7.0
	github.com/google/go-tpm v0.9.7
	github.com/google/go-tpm-tools v0.4.4
	github.com/openbao/openbao/deviceattestpoc/proto v0.0.0
	google.golang.org/grpc v1.70.0
)

require (
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/go-configfs-tsm v0.2.2 // indirect
	github.com/google/go-sev-guest v0.9.3 // indirect
	github.com/google/go-tdx-guest v0.3.1 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250124145028-65684f501c47 // indirect
	google.golang.org/protobuf v1.36.4 // indirect
)

replace github.com/openbao/openbao/deviceattestpoc/proto => ../proto
