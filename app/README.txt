New Folders:

app: Contains files to run hop client and hop server along with sample keys/certs.
authgrants: provides data structures and functions necessary for the authorization grant protocol
codex: provides data structures and functions necessary for code execution channels
npc: provides data structures and functions necessary for network proxy channels

Also Modified:

channels: 
    - added methods to Reliable channels + modified frame retransmission to fix laggy terminal echo
transport: 
    - added capability to use a Reliable channel as underlying connection
    - introduced authorized key logic

Done: 
- store authorization grants in memory instead of authorized_keys file (!!!!)
- Principal needs to get user input as a background process (!!!) --> semi-fixed, still have one weird line. Don't know how to make a GUI cmd line app but could work if exec.CMD? Another process?
- Server checks cmd against auth grant before running (maybe made this unnecessarily complex)
- switched to abstract sockets
- test on multiple VMS (!!!)
- Unix domain socket address standard
- thread safety of maps to principal sessions (muxers) (!!)

Miscellaneous Issues/TODOs:
- start hop client as specified user (!!!)
- add timeouts/deadlines (!!!)
- authorized_keys file location standard (!!!) (.hop/authorized_keys)
- keys default location (.hop/<key_name>) (still have to specify path?)

- parse cmd intelligently (have to move away from exec.Cmd?) (!!)
- check codex.Server() for issues relating to pty/terminal display crap (!!)

- change all "channels" -> "tubes"
- fine tune constants in channels/muxer code
- should server 2 somehow check a security policy or something before adding authgrant? (Like make sure that the principal is allowed to give authgrants?)

