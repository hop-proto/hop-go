package hopclient

import (
	"hop.computer/hop/tubes"
)

// start session between principal and target proxied through the delegate
// func (c *HopClient) setupRemoteSession(req *authgrants.Intent) (*HopClient, error) {
// 	panic("update me!")
//logrus.Info("C: USER CONFIRMED FIRST INTENT_REQUEST. CONTACTING S2...")

// //create netproxy with server
// npt, err := c.TubeMuxer.CreateTube(common.NetProxyTube)
// logrus.Info("started netproxy tube from principal")
// if err != nil {
// 	logrus.Fatal("C: Error starting netproxy tube")
// }

// hostname, port := req.Address()
// err = netproxy.Start(npt, net.JoinHostPort(hostname, port), netproxy.AG)
// if err != nil {
// 	logrus.Error("Issue proxying connection")
// 	return nil, err
// }

// subConfig := c.config
// u := core.URL{
// 	Host: hostname,
// 	Port: port,
// 	User: req.Username(),
// }
// subsess, err := NewHopClient(&subConfig)
// if err != nil {
// 	logrus.Error("Issue creating client")
// 	return nil, err
// }
// subsess.Proxied = true
// subsess.ProxyConn = npt

// // TODO(dadrian): How do we get an authenticator to the dialer?
// err = subsess.Dial(u.Address(), nil)
// if err != nil {
// 	logrus.Error("Issue starting underlying connection")
// 	return nil, err
// }
// subsess.TubeMuxer = tubes.NewMuxer(subsess.TransportConn, subsess.TransportConn)
// go subsess.TubeMuxer.Start()

// err = subsess.userAuthorization()
// if err != nil {
// 	logrus.Error("Failed user authorization")
// 	return nil, err
// }
// // Want to keep this session open in case the "server 2" wants to continue chaining hop sessions together
// // TODO(baumanl): Simplify this. Should only get authorization grant tubes?
// go subsess.HandleTubes()

// return subsess, nil
// }

// start an authorization grant connection with the remote server and send intent request. return response.
// func (c *HopClient) confirmWithRemote(req *authgrants.Intent, npAgc *authgrants.AuthGrantConn, agt *authgrants.AuthGrantConn) ([]byte, error) {
// 	//send INTENT_COMMUNICATION
// 	e := npAgc.SendIntentCommunication(req)
// 	if e != nil {
// 		logrus.Info("Issue writing intent comm to netproxyAgc")
// 	}
// 	logrus.Info("sent intent comm")
// 	_, response, e := npAgc.ReadResponse()
// 	if e != nil {
// 		logrus.Errorf("C: error reading from agc: %v", e)
// 		return nil, e
// 	}
// 	logrus.Info("got response")
// 	return response, nil
// }

// reroutes remote port forwarding connections to the appropriate destination
// TODO(baumanl): add ability to handle multiple PF relationships
func (c *HopClient) handleRemote(tube tubes.Tube) error {
	panic("update me!")
	// defer tube.Close()
	// //if multiple remote pf relationships, figure out which one this corresponds to
	// b := make([]byte, 4)
	// tube.Read(b)
	// l := binary.BigEndian.Uint32(b[0:4])
	// logrus.Infof("Expecting %v bytes", l)
	// init := make([]byte, l)
	// tube.Read(init)
	// arg := string(init)
	// found := false
	// for _, v := range c.config.RemoteArgs {
	// 	if v == arg {
	// 		found = true
	// 	}
	// }
	// if !found {
	// 	logrus.Error()
	// }
	// tube.Write([]byte{netproxy.NpcConf})

	// //handle another remote pf conn (rewire to dest)
	// logrus.Info("Doing remote with: ", arg)

	// fwdStruct := portforwarding.Fwd{
	// 	Listensock:        false,
	// 	Connectsock:       false,
	// 	Listenhost:        "",
	// 	Listenportorpath:  "",
	// 	Connecthost:       "",
	// 	Connectportorpath: "",
	// }
	// err := portforwarding.ParseForward(arg, &fwdStruct)
	// if err != nil {
	// 	return err
	// }

	// var tconn net.Conn
	// if !fwdStruct.Connectsock {
	// 	addr := net.JoinHostPort(fwdStruct.Connecthost, fwdStruct.Connectportorpath)
	// 	if _, err := net.LookupAddr(addr); err != nil {
	// 		//Couldn't resolve address with local resolver
	// 		logrus.Error(err)
	// 		return err
	// 	}
	// 	logrus.Infof("dialing dest: %v", addr)
	// 	tconn, err = net.Dial("tcp", addr)
	// } else {
	// 	logrus.Infof("dialing dest: %v", fwdStruct.Connectportorpath)
	// 	tconn, err = net.Dial("unix", fwdStruct.Connectportorpath)
	// }
	// if err != nil {
	// 	logrus.Error(err)
	// 	return err
	// }

	// wg := sync.WaitGroup{}
	// //do remote port forwarding
	// wg.Add(1)
	// go func() {
	// 	defer wg.Done()
	// 	n, _ := io.Copy(tube, tconn)
	// 	logrus.Infof("Copied %v bytes from tconn to tube", n)
	// }()

	// n, _ := io.Copy(tconn, tube)
	// tconn.Close()
	// logrus.Infof("Copied %v bytes from tube to tconn", n)
	// wg.Wait()
	// return nil
}

// // client initiates remote port forwarding and sends the server the info it needs
// func (c *HopClient) remoteForward(arg string) error {
// 	logrus.Info("Setting up remote with: ", arg)
// 	npt, e := c.TubeMuxer.CreateTube(common.RemotePFTube)
// 	if e != nil {
// 		return e
// 	}
// 	e = netproxy.Start(npt, arg, netproxy.Remote)
// 	return e
// }

// func (c *HopClient) localForward(arg string) error {
// 	logrus.Info("Doing local with: ", arg)
// 	fwdStruct := portforwarding.Fwd{
// 		Listensock:        false,
// 		Connectsock:       false,
// 		Listenhost:        "",
// 		Listenportorpath:  "",
// 		Connecthost:       "",
// 		Connectportorpath: "",
// 	}
// 	err := portforwarding.ParseForward(arg, &fwdStruct)
// 	if err != nil {
// 		return err
// 	}
// 	var local net.Listener
// 	if !fwdStruct.Listensock { //bind to local address
// 		localAddr := net.JoinHostPort(fwdStruct.Listenhost, fwdStruct.Listenportorpath)
// 		local, err = net.Listen("tcp", localAddr)
// 		if err != nil {
// 			logrus.Error("host:port listen error: ", err)
// 			return err
// 		}
// 	} else {
// 		local, err = net.Listen("unix", fwdStruct.Listenportorpath)
// 		if err != nil {
// 			logrus.Error("socket listen error: ", err)
// 			return err
// 		}
// 	}

// 	go func() {
// 		//do local port forwarding
// 		if c.config.Headless {
// 			defer c.wg.Done()
// 		}
// 		//accept incoming connections
// 		regchan := make(chan net.Conn)
// 		go func() {
// 			for {
// 				localConn, e := local.Accept()
// 				if e != nil {
// 					logrus.Error(e)
// 					break
// 				}
// 				logrus.Info("Accepted TCPConn...")
// 				regchan <- localConn
// 			}
// 		}()

// 		for {
// 			lconn := <-regchan
// 			go func() { //start tube with server for new connection
// 				npt, e := c.TubeMuxer.CreateTube(common.LocalPFTube)
// 				if e != nil {
// 					return
// 				}
// 				defer npt.Close()
// 				e = netproxy.Start(npt, arg, netproxy.Local)
// 				if e != nil {
// 					return
// 				}
// 				if c.config.Headless {
// 					c.wg.Add(1)
// 				}
// 				go func() {
// 					n, _ := io.Copy(npt, lconn)
// 					npt.Close()
// 					logrus.Debugf("Copied %v bytes from lconn to npt", n)
// 					logrus.Info("tconn ended")
// 				}()
// 				n, _ := io.Copy(lconn, npt)
// 				lconn.Close()
// 				logrus.Debugf("Copied %v bytes from npt to lconn", n)
// 			}()
// 		}
// 	}()
// 	return nil
// }
