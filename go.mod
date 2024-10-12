module hop.computer/hop

go 1.23

replace github.com/BurntSushi/toml => github.com/drebelsky/toml v0.0.2

require (
	github.com/AstromechZA/etcpwdparse v0.0.0-20170319193008-f0e5f0779716
	github.com/BurntSushi/toml v1.2.0
	github.com/creack/pty v1.1.18
	github.com/docker/docker v20.10.14+incompatible
	github.com/docker/go-connections v0.4.0
	github.com/mattn/go-isatty v0.0.14
	github.com/pkg/errors v0.9.1
	github.com/sbinet/pstree v0.3.0
	github.com/sirupsen/logrus v1.8.1
	github.com/vektra/tai64n v0.0.0-20180410233929-12133dfe3281
	goji.io v2.0.2+incompatible
	golang.org/x/crypto v0.0.0-20220427172511-eb4f295cb31f
	golang.org/x/exp v0.0.0-20221215174704-0915cd710c24
	golang.org/x/sys v0.1.0
	golang.org/x/term v0.0.0-20220411215600-e5f449aeb171
	gotest.tools v2.2.0+incompatible
)

require golang.org/x/net v0.0.0-20220425223048-2871e0cb64e4 // indirect

require (
	github.com/Microsoft/go-winio v0.5.2 // indirect
	github.com/Microsoft/hcsshim v0.9.2 // indirect
	github.com/containerd/cgroups v1.0.3 // indirect
	github.com/containerd/containerd v1.6.3 // indirect
	github.com/docker/distribution v2.8.1+incompatible // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.5.8 // indirect
	github.com/mitchellh/go-ps v1.0.0
	github.com/moby/sys/mount v0.3.2 // indirect
	github.com/moby/sys/mountinfo v0.6.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.3-0.20211202183452-c5a74bcca799 // indirect
	github.com/opencontainers/runc v1.1.1 // indirect
	go.opencensus.io v0.23.0 // indirect
	go.uber.org/goleak v1.2.0
	google.golang.org/genproto v0.0.0-20220426171045-31bebdecfb46 // indirect
	google.golang.org/grpc v1.46.0 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
)
