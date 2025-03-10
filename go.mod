module hop.computer/hop

go 1.23

replace github.com/BurntSushi/toml => github.com/drebelsky/toml v0.0.2

require (
	github.com/AstromechZA/etcpwdparse v0.0.0-20170319193008-f0e5f0779716
	github.com/BurntSushi/toml v1.2.0
	github.com/creack/pty v1.1.18
	github.com/mattn/go-isatty v0.0.14
	github.com/muesli/cancelreader v0.2.2
	github.com/pkg/errors v0.9.1
	github.com/sbinet/pstree v0.3.0
	github.com/sirupsen/logrus v1.8.1
	goji.io v2.0.2+incompatible
	golang.org/x/crypto v0.0.0-20220427172511-eb4f295cb31f
	golang.org/x/exp v0.0.0-20221215174704-0915cd710c24
	golang.org/x/sys v0.1.0
	golang.org/x/term v0.0.0-20220411215600-e5f449aeb171
	gotest.tools v2.2.0+incompatible
)

require (
	github.com/gosuri/uilive v0.0.4 // indirect
	golang.org/x/lint v0.0.0-20200302205851-738671d3881b // indirect
)

require (
	github.com/google/go-cmp v0.5.8 // indirect
	github.com/mitchellh/go-ps v1.0.0
	go.uber.org/goleak v1.2.0
)
