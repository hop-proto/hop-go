## New Folders:

- app: Contains main logic for hop client and hop server.
- authgrants: provides data structures and functions necessary for the authorization grant protocol
- codex: provides data structures and functions necessary for code execution tubes
- netproxy: provides data structures and functions necessary for network proxy tubes
- userauth: provides data structures and functions necessary for user authorization tubes
- cmd/hop: build hop executable
- cmd/hopd: build hopd executable
- cmd/hop-keygen: program to generate keypair and store in default location

## Also Modified:

- tubes: 
    - added methods to Reliable tubes + modified frame retransmission to fix laggy terminal echo
- transport: 
    - added capability to use a Reliable tube as underlying connection

## Miscellaneous Issues/TODOs:
- close netproxied session from principal -> target after delegate uses authgrant and session ends (!!!)
- add timeouts/deadlines (!!!)
- add option to run specified command in a shell instead of directly with exec.Command (allows for intelligent parsing + piping and stuff) (!!)
- update Intent struct
- add unreliable tubes
- switch Netproxy to use unreliable tube as underlying conn
- add server/client config files
- check codex.Server() for issues relating to pty/terminal display crap (!!)
- fine tune constants in tubes/muxer code
- should server 2 somehow check a security policy or something before adding authgrant? (Like make sure that the principal is allowed to give authgrants?)

## Done: 
- set authgrant budget (how many outstanding authgrants should a server allowed)
- needs to check userhomedir/.hop/authorized_keys
- keys default location (.hop/<key_name>) (still have to specify path?)
- start hop client as specified user (!!!)
- reorganize user authentication (separate from transport layer client authentication) (!!!!)
- store authorization grants in memory instead of authorized_keys file (!!!!)
- Principal needs to get user input as a background process (!!!) --> semi-fixed, still have one weird line. Don't know how to make a GUI cmd line app but could work if exec.CMD? Another process?
- Server checks cmd against auth grant before running (maybe made this unnecessarily complex)
- switched to abstract sockets
- test on multiple VMS (!!!)
- Unix domain socket address standard
- thread safety of maps to principal sessions (muxers) (!!)
- authorized_keys file location standard (!!!) (~/.hop/authorized_keys)