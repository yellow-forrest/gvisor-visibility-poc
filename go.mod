module github.com/yellow-forrest/gvisor-visibility-poc

go 1.24

require google.golang.org/protobuf v1.34.2

// Local replaces so the PoC builds fully offline (no module proxy needed).
// Point these at pinned upstream clones; remove them to build against the proxy.
replace (
	github.com/golang/protobuf => ./third_party/golang-protobuf
	github.com/google/go-cmp => ./third_party/go-cmp
	google.golang.org/protobuf => ./third_party/protobuf-go
)
