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


Miscellaneous Issues/TODOs:

- Principal needs to get user input as a background process (!!!) --> semi-fixed, still have one weird line. Don't know how to make a GUI cmd line app but could work if exec.CMD? Another process?

- fixed laggy typing echo, but getting stdout from channel seems laggy -> Adjust max data length params

- start hop client as specified user 

- oneshot command functionality
- exiting from bash or other cmd --> restore client terminal to original shell

- parse cmd intelligently (have to move away from exec.Cmd?)


-thread safety of maps to principal sessions (muxers)

-check codex.Server() for issues relating to pty/terminal display crap


- Unix domain socket address standard --> convert to abstract sockets???
- authorized_keys file location standard

- how should server set deadline for authgrant?
- should server 2 somehow check a security policy or something before adding authgrant? (Like make sure that the principal is allowed to give authgrants?)

- Better error handling
- Commenting
- More idiomatic go code
- better decomp/abstraction
-struct for "session" instead of directly using muxers???
- Closing/Exit behavior

