module github.com/sardanioss/httpcloak

go 1.24.1

retract (
	v1.4.0 // Published prematurely, use v1.1.x instead
	v1.3.0 // Published prematurely, use v1.1.x instead
	v1.2.0 // Published prematurely, use v1.1.x instead
)

require (
	github.com/andybalholm/brotli v1.2.0
	github.com/klauspost/compress v1.18.2
	github.com/miekg/dns v1.1.69
	github.com/sardanioss/http v1.1.0
	github.com/sardanioss/net v1.1.0
	github.com/sardanioss/quic-go v1.2.13
	github.com/sardanioss/utls v1.9.5
)

require (
	github.com/dunglas/httpsfv v1.0.2 // indirect
	github.com/quic-go/masque-go v0.3.0 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	github.com/quic-go/quic-go v0.53.0 // indirect
	github.com/sardanioss/qpack v0.6.2 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	go.uber.org/mock v0.5.2 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/mod v0.30.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	golang.org/x/tools v0.39.0 // indirect
)
