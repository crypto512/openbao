module github.com/openbao/openbao/deviceattestpoc/client

go 1.23

require (
	github.com/fxamacker/cbor/v2 v2.7.0
	github.com/google/go-attestation v0.5.1
	github.com/google/go-tpm v0.9.3
	github.com/openbao/openbao/deviceattestpoc/proto v0.0.0
	google.golang.org/grpc v1.70.0
)

require (
	github.com/google/certificate-transparency-go v1.2.2 // indirect
	github.com/google/go-tpm-tools v0.4.4 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.32.0 // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250124145028-65684f501c47 // indirect
	google.golang.org/protobuf v1.36.4 // indirect
)

replace github.com/openbao/openbao/deviceattestpoc/proto => ../proto
