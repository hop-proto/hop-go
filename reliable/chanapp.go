package main

type ChannelApp struct {
	nm *NetworkManager
}

func (ca *ChannelApp) start(nm *NetworkManager){
	ca.nm = nm
}

func (ca *ChannelApp) shutdown(){
	ca.nm.shutdown()
}
