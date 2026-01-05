module github.com/sardanioss/httpcloak

go 1.24.0

require (
	github.com/andybalholm/brotli v1.1.1
	github.com/klauspost/compress v1.18.2
	github.com/sardanioss/net v0.1.0
	github.com/sardanioss/quic-go v0.1.0
	github.com/sardanioss/utls v0.1.0
)

require (
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
)

replace github.com/sardanioss/net => ./temp/sardanioss-net

replace github.com/sardanioss/utls => ./temp/sardanioss-utls

replace github.com/sardanioss/quic-go => ./temp/sardanioss-quic-go
