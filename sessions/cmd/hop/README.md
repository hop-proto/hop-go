# ssh-app

This is a custom script for an sshd daemon and ssh client. This is intended as POC code to test the primary hop layers end-to-end.
Unix privileges and permissions, isolation, authentication, and security review are still TODO.

SSH Server Usage: `go build && ./hop sshd`

SSH Client Usage: `go build && ./hop ssh`