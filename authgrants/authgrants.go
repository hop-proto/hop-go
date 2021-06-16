package authgrants

//MSG Types
const INTENT_REQUEST = 0
const INTENT_COMMUNICATION = 1
const INTENT_CONFIRMATION = 2
const INTENT_DENIED = 3

/*How the principal should respond to different authorization
grant message types*/
func principalHandleMsg(msg []byte) {
	msgType := msg[0]
	switch msgType {
	case INTENT_REQUEST:
		clientID := msg[1:33] //first 32 bytes of data
		// SNI := //next 256 bytes;
		// aport := //next 2 bytes
		// channelType := //next byte
		// reserved := //next byte
		// assocData := //remaining bytes (desired command to run)
		//Prompt user with request
		//send INTENT_DENIED to client if user denies
		//otherwise initiate network proxy channel w/ client
		//initiate hop session with server through proxy channel w/ client
		//send INTENT_COMMUNICATION msg to server

	case INTENT_CONFIRMATION:
		//if this msg came from the server that we previously sent an INTENT_COMMUNICATION to...
		//data := timestamp deadline set by the server for the client to complete the Hop handshake
		//forward this message to the client
		//otherwise error

	case INTENT_DENIED:
		//if this msg came from the server that we previously sent an INTENT_COMMUNICATION to...
		//data := //reason for denial
		//forward this message to the client
		//otherwise error

	default:
		//error
	}
}

/*How the server should respond to different Auth Grant msg types */
func serverHandleMsg(msg []byte) {
	msgType := msg[0]
	switch msgType {
	case INTENT_COMMUNICATION:
		// clientID := msg[1:33]//first 32 bytes of data
		// SNI := //next 256 bytes
		// port := //next 2 bytes
		// channelType := //next byte
		// reserved := //next byte
		// assocData := //remaining bytes (desired command to run)
		// //Check server policies
		// //send INTENT_CONFIRMATION or INTENT_DENIED

	default:
		//error
	}
}

/*how the client should respond*/
func clientHandleMsg(msg []byte) {
	msgType := msg[0]
	switch msgType {
	case INTENT_CONFIRMATION:
		//data := //timestamp deadline set by the server for the client to complete the Hop handshake
	case INTENT_DENIED:
		//data := //reason for denial

	default:
		//error
	}
}
