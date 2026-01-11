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
	github.com/sardanioss/quic-go v1.2.14
	github.com/sardanioss/utls v1.9.8
)

require (
	github.com/sardanioss/qpack v0.6.2 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/mod v0.30.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	golang.org/x/tools v0.39.0 // indirect
)

replace github.com/sardanioss/utls => /home/saksham/own_tools/utls

replace github.com/sardanioss/quic-go => /home/saksham/own_tools/quic-go
