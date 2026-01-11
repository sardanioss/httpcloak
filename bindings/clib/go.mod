module httpcloak-clib

go 1.24.1

require github.com/sardanioss/httpcloak v1.0.4

require (
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/klauspost/compress v1.18.2 // indirect
	github.com/miekg/dns v1.1.69 // indirect
	github.com/sardanioss/http v1.1.0 // indirect
	github.com/sardanioss/net v1.1.0 // indirect
	github.com/sardanioss/qpack v0.6.2 // indirect
	github.com/sardanioss/quic-go v1.2.14 // indirect
	github.com/sardanioss/utls v1.9.8 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/mod v0.30.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	golang.org/x/tools v0.39.0 // indirect
)

// Use local httpcloak package
replace github.com/sardanioss/httpcloak => ../..

// Use local utls with StoreSession fix
replace github.com/sardanioss/utls => /home/saksham/own_tools/utls

// Use local quic-go with StoreSession and ClientSessionCache fixes
replace github.com/sardanioss/quic-go => /home/saksham/own_tools/quic-go
