package hopclient

import "errors"

const clientUsage = "hop [user@]host[:port] [-K or -k path] [-L port:host:hostport] [-R port:host:hostport] [-N] [-c cmd] [-q] [-h]"

//ErrClientInvalidUsage returned by client when unable to parse command line arguments
var ErrClientInvalidUsage = errors.New("usage: " + clientUsage)

//ErrClientLoadingKeys returned by client (principal) when unable to load keys from specified location
var ErrClientLoadingKeys = errors.New("unable to load keys")

//ErrClientGettingAuthorization  is returned by client when it can't get
var ErrClientGettingAuthorization = errors.New("failed to get authorization")

//ErrClientStartingUnderlying is returned by client when it can't start transport layer conn
var ErrClientStartingUnderlying = errors.New("error starting underlying conn")

//ErrClientUnauthorized is returned by client when it is not authorized to perform the action it requested
var ErrClientUnauthorized = errors.New("client not authorized")

//ErrClientStartingExecTube is returned by client when cmd execution and/or I/O redirection fails
var ErrClientStartingExecTube = errors.New("failed to start session")
