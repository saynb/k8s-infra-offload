// Copyright (c) 2022 Intel Corporation.  All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License")
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"context"
	"fmt"
	"net"
	"os"
	"reflect"

	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	pb "github.com/ipdk-io/k8s-infra-offload/proto"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/tomb.v2"
)

var (
	grpcDial              = grpc.Dial
	pbNewInfraAgentClient = pb.NewInfraAgentClient
	cancellableListener   = getCancellableListener
	removeSocket          = os.RemoveAll
)

type SyncState int

const (
	StateDisconnected SyncState = iota
	StateConnected
	StateSyncing
	StateInSync
)

type PolicyServer struct {
	log           *logrus.Entry
	nextSeqNumber uint64
	exiting       chan bool
	name          string
	policyState   *PolicyState
	syncState     SyncState
}

func NewPolicyServer(log *logrus.Entry) (types.Server, error) {
	return &PolicyServer{
		log:           log,
		nextSeqNumber: 0,
		exiting:       make(chan bool),
		name:          "felix-policy-server",
		syncState:     StateDisconnected,
		policyState:   NewPolicyState()}, nil
}

func (s *PolicyServer) GetName() string {
	return s.name
}

func (s *PolicyServer) SyncPolicy(conn net.Conn) {
	for {
		msg, err := s.RecvMessage(conn)
		if err != nil {
			s.log.WithError(err).Warn("error communicating with felix")
			conn.Close()
			return
		}
		s.log.Infof("Got message from felix %T", msg)
		switch m := msg.(type) {
		case *pb.ConfigUpdate:
			err = s.handleConfigUpdate(m)
		case *pb.InSync:
			err = s.handleInSyc(m)
		default:
			// TODO @Abdul for what I saw in my test in-sync is received only onec, after initial handshake
			// in our current solution does it make sense to store incomming request just to send them
			// after receiving in-sync ?
			var pending bool
			if s.syncState == StateSyncing {
				pending = true
			} else if s.syncState == StateInSync {
				pending = false
			}
			err = s.handleMessage(msg, pending)
		}
		if err != nil {
			s.log.WithError(err).Warn("Error processing update from felix, restarting")
			conn.Close()
			s.syncState = StateDisconnected
			return
		}

	}
}

func (s *PolicyServer) handleMessage(msg interface{}, pending bool) error {
	switch m := msg.(type) {
	case *pb.IPSetUpdate:
		return s.handleIpsetUpdate(m, pending)
	case *pb.IPSetDeltaUpdate:
		return s.handleIpsetDeltaUpdate(m, pending)
	case *pb.IPSetRemove:
		return s.handleIpsetRemove(m, pending)
	case *pb.ActivePolicyUpdate:
		return s.handleActivePolicyUpdate(m, pending)
	case *pb.ActivePolicyRemove:
		return s.handleActivePolicyRemove(m, pending)
	case *pb.ActiveProfileUpdate:
		return s.handleActiveProfileUpdate(m, pending)
	case *pb.ActiveProfileRemove:
		return s.handleActiveProfileRemove(m, pending)
	case *pb.HostEndpointUpdate:
		return s.handleHostEndpointUpdate(m, pending)
	case *pb.HostEndpointRemove:
		return s.handleHostEndpointRemove(m, pending)
	case *pb.WorkloadEndpointUpdate:
		return s.handleWorkloadEndpointUpdate(m, pending)
	case *pb.WorkloadEndpointRemove:
		return s.handleWorkloadEndpointRemove(m, pending)
	case *pb.HostMetadataUpdate:
		return s.handleHostMetadataUpdate(m, pending)
	case *pb.HostMetadataRemove:
		return s.handleHostMetadataRemove(m, pending)
	case *pb.IPAMPoolUpdate:
		return s.handleIpamPoolUpdate(m, pending)
	case *pb.IPAMPoolRemove:
		return s.handleIpamPoolRemove(m, pending)
	case *pb.ServiceAccountUpdate:
		return s.handleServiceAccountUpdate(m, pending)
	case *pb.ServiceAccountRemove:
		return s.handleServiceAccountRemove(m, pending)
	case *pb.NamespaceUpdate:
		return s.handleNamespaceUpdate(m, pending)
	case *pb.NamespaceRemove:
		return s.handleNamespaceRemove(m, pending)
	case *pb.RouteUpdate:
		return s.handleRouteUpdate(m, pending)
	case *pb.RouteRemove:
		return s.handleRouteRemove(m, pending)
	case *pb.VXLANTunnelEndpointRemove:
		return s.handleVXLANTunnelEndpointRemove(m, pending)
	case *pb.VXLANTunnelEndpointUpdate:
		return s.handleVXLANTunnelEndpointUpdate(m, pending)
	case *pb.WireguardEndpointUpdate:
		return s.handleWireguardEndpointUpdate(m, pending)
	case *pb.WireguardEndpointRemove:
		return s.handleWireguardEndpointRemove(m, pending)
	case *pb.GlobalBGPConfigUpdate:
		return s.handleGlobalBGPConfigUpdate(m, pending)
	default:
		s.log.Warnf("Unhandled message from felix: %v", m)
	}
	return nil
}

func (s *PolicyServer) StopServer() {
	s.exiting <- true
}

// Not needed?
func (s *PolicyServer) handleConfigUpdate(msg *pb.ConfigUpdate) error {
	s.log.Infof("Got config update %+v", msg)
	s.syncState = StateSyncing
	return nil
}

func (s *PolicyServer) handleInSyc(msg *pb.InSync) error {
	s.log.Infof("Got in sync %+v", msg)
	// TODO Abdul pending is now configured state in current solution what we should do ?
	for m := range s.policyState.pendingState.Iterate() {
		// we are in-sync send all messages
		s.log.Infof("Will send %T", m)
		if err := s.handleMessage(m, false); err != nil {
			//TODO Abdul what to do here
			s.log.WithError(err).Error("error occur while handling pending state")
		}
	}
	// TODO Abdul after hendling s.policyState.configuredState == s.policyState.pendingState
	// what to do next ?
	s.policyState.pendingState = NewOrderedDict()
	// after sendign all message send in sync
	out := &pb.Reply{
		Successful: true,
	}
	c, conn, err := s.dialManager()
	if err != nil {
		return errors.Wrap(err, "cannot process handleIpsetUpdate: cannot dial manager")
	}
	out, err = c.InSync(context.TODO(), &pb.Sync{})
	if err != nil || !out.Successful {
		return errors.Wrap(err, "cannot process handleInSync")
	}
	conn.Close()
	s.syncState = StateInSync
	return nil
}

func (s *PolicyServer) handleIpsetUpdate(msg *pb.IPSetUpdate, pending bool) error {
	s.log.Infof("Got ipset update %+v pending %v", msg, pending)
	if pending {
		s.policyState.pendingState.Set(msg.Id, msg)
	} else {
		configured := s.policyState.configuredState.Get(msg.Id)
		if configured != nil && reflect.DeepEqual(configured, msg) {
			//TODO Abdul update is not required return
			return nil
		}
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleIpsetUpdate: cannot dial manager")
		}
		defer conn.Close()
		out, err = c.UpdateIPSet(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleIpsetUpdate")
		}
		s.policyState.configuredState.Set(msg.Id, msg)
	}
	return nil
}

func (s *PolicyServer) handleIpsetDeltaUpdate(msg *pb.IPSetDeltaUpdate, pending bool) error {
	s.log.Infof("Got ipset delta update %+v, pending %v", msg, pending)
	if pending {
		s.policyState.pendingState.Set(msg.Id, msg)
	} else {
		configured := s.policyState.configuredState.Get(msg.Id)
		if configured != nil && reflect.DeepEqual(configured, msg) {
			//TODO Abdul update is not required return
			return nil
		}
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleIpsetDeltaUpdate: cannot dial manager")
		}
		defer conn.Close()
		out, err = c.UpdateIPSetDelta(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleIpsetDeltaUpdate")

		}
		s.policyState.configuredState.Set(msg.Id, msg)
	}
	return nil
}

func (s *PolicyServer) handleIpsetRemove(msg *pb.IPSetRemove, pending bool) error {
	s.log.Infof("Got ipset remove %+v, pending %v", msg, pending)
	if pending {
		s.policyState.pendingState.Set(msg.Id, msg)
	} else {
		// TODO Abdul not sure is we should skip Remove so I leave it
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleIpsetRemove: cannot dial manager")
		}
		defer conn.Close()
		out, err = c.RemoveIPSet(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleIpsetRemove")
		}
		s.policyState.configuredState.Set(msg.Id, msg)
	}
	return nil
}

func (s *PolicyServer) handleActivePolicyUpdate(msg *pb.ActivePolicyUpdate, pending bool) error {
	s.log.Infof("Got active police update %+v, pending %v", msg, pending)
	if pending {
		s.policyState.pendingState.Set(msg.Id.String(), msg)
	} else {
		configured := s.policyState.configuredState.Get(msg.Id.String())
		if configured != nil && reflect.DeepEqual(configured, msg) {
			//TODO Abdul update is not required return
			return nil
		}
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleActivePolicyUpdate: cannot dial manager")
		}
		defer conn.Close()
		out, err = c.ActivePolicyUpdate(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleActivePolicyUpdate")
		}
		s.policyState.configuredState.Set(msg.Id.String(), msg)
	}
	return nil
}

func (s *PolicyServer) handleActivePolicyRemove(msg *pb.ActivePolicyRemove, pending bool) error {
	s.log.Infof("Got active police remove %+v, pending %v", msg, pending)
	if pending {
		s.policyState.pendingState.Set(msg.Id.String(), msg)
	} else {
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleActivePolicyRemove: cannot dial manager")
		}
		defer conn.Close()
		out, err = c.ActivePolicyRemove(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleActivePolicyRemove")
		}
		s.policyState.configuredState.Set(msg.Id.String(), msg)
	}

	return nil
}

func (s *PolicyServer) handleActiveProfileUpdate(msg *pb.ActiveProfileUpdate, pending bool) error {
	s.log.Infof("Got active profile update %+v, pending %v", msg, pending)
	if pending {
		s.policyState.pendingState.Set(msg.Id.String(), msg)
	} else {
		configured := s.policyState.configuredState.Get(msg.Id.String())
		if configured != nil && reflect.DeepEqual(configured, msg) {
			//TODO Abdul update is not required return
			return nil
		}
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleActiveProfileUpdate: cannot dial manager")
		}
		defer conn.Close()
		out, err = c.UpdateActiveProfile(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleActiveProfileUpdate")
		}
		s.policyState.configuredState.Set(msg.Id.String(), msg)
	}
	return nil
}

func (s *PolicyServer) handleActiveProfileRemove(msg *pb.ActiveProfileRemove, pending bool) error {
	s.log.Infof("Got active profile remove %+v, pending %v", msg, pending)
	if pending {
		s.policyState.pendingState.Set(msg.Id.String(), msg)
	} else {
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleActiveProfileRemove: cannot dial manager")
		}
		defer conn.Close()
		out, err = c.RemoveActiveProfile(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleActiveProfileRemove")
		}
		s.policyState.configuredState.Set(msg.Id.String(), msg)
	}
	return nil
}

func (s *PolicyServer) handleHostEndpointUpdate(msg *pb.HostEndpointUpdate, pending bool) error {
	s.log.Infof("Got host endpoint update %+v, pending %v", msg, pending)
	if pending {
		s.policyState.pendingState.Set(msg.Id.String(), msg)
	} else {
		configured := s.policyState.configuredState.Get(msg.Id.String())
		if configured != nil && reflect.DeepEqual(configured, msg) {
			//TODO Abdul update is not required return
			return nil
		}
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleHostEndpointUpdate: cannot dial manager")
		}
		defer conn.Close()
		out, err = c.UpdateHostEndpoint(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleHostEndpointUpdate")
		}
		s.policyState.configuredState.Set(msg.Id.String(), msg)
	}

	return nil
}

func (s *PolicyServer) handleHostEndpointRemove(msg *pb.HostEndpointRemove, pending bool) error {
	s.log.Infof("Got host endpoint remove %+v, pending %v", msg, pending)
	if pending {
		s.policyState.pendingState.Set(msg.Id.String(), msg)
	} else {
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleHostEndpointRemove: cannot dial manager")
		}
		defer conn.Close()
		out, err = c.RemoveHostEndpoint(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleHostEndpointRemove")
		}
		s.policyState.configuredState.Set(msg.Id.String(), msg)
	}
	return nil
}

func (s *PolicyServer) handleWorkloadEndpointUpdate(msg *pb.WorkloadEndpointUpdate, pending bool) error {
	s.log.Infof("Got workload endpoint update %+v, pending %v", msg, pending)
	if pending {
		s.policyState.pendingState.Set(msg.Id.String(), msg)
	} else {
		configured := s.policyState.configuredState.Get(msg.Id.String())
		if configured != nil && reflect.DeepEqual(configured, msg) {
			//TODO Abdul update is not required return
			return nil
		}
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleWorkloadEndpointUpdate: cannot dial manager")
		}
		defer conn.Close()
		out, err = c.UpdateLocalEndpoint(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleWorkloadEndpointUpdate")
		}
		s.policyState.configuredState.Set(msg.Id.String(), msg)
	}

	return nil
}

func (s *PolicyServer) handleWorkloadEndpointRemove(msg *pb.WorkloadEndpointRemove, pending bool) error {
	s.log.Infof("Got workload endpoint remove %+v, pending %v", msg, pending)
	if pending {
		s.policyState.pendingState.Set(msg.Id.String(), msg)
	} else {
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleWorkloadEndpointRemove: cannot dial manager")
		}
		defer conn.Close()

		out, err = c.RemoveLocalEndpoint(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleWorkloadEndpointRemove")
		}
		s.policyState.configuredState.Set(msg.Id.String(), msg)
	}
	return nil
}

func (s *PolicyServer) handleHostMetadataUpdate(msg *pb.HostMetadataUpdate, pending bool) error {
	s.log.Infof("Got host metadata update %+v, pending %v", msg, pending)
	id := "metadata" + msg.Hostname
	if pending {
		// message does not have ID fake it
		s.policyState.pendingState.Set(id, msg)
	} else {
		configured := s.policyState.configuredState.Get(id)
		if configured != nil && reflect.DeepEqual(configured, msg) {
			//TODO Abdul update is not required return
			return nil
		}
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleHostMetadataUpdate: cannot dial manager")
		}
		defer conn.Close()
		out, err = c.UpdateHostMetaData(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleHostMetadataUpdate")
		}
		s.policyState.configuredState.Set(id, msg)
	}

	return nil
}

func (s *PolicyServer) handleHostMetadataRemove(msg *pb.HostMetadataRemove, pending bool) error {
	s.log.Infof("Got host metadata remove %+v, pending %v", msg, pending)
	id := "metadata" + msg.Hostname
	if pending {
		// message does not have ID fake it
		s.policyState.pendingState.Set(id, msg)
	} else {
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleHostMetadataRemove: cannot dial manager")
		}
		defer conn.Close()
		out, err = c.RemoveHostMetaData(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleHostMetadataRemove")
		}
		s.policyState.configuredState.Set(id, msg)
	}

	return nil
}

// Not needed?
func (s *PolicyServer) handleIpamPoolUpdate(msg *pb.IPAMPoolUpdate, pending bool) error {
	s.log.Infof("Got ipam pool update %+v, pending %v", msg, pending)
	if pending {
		s.policyState.pendingState.Set(msg.Id, msg)
	} else {
		configured := s.policyState.configuredState.Get(msg.Id)
		if configured != nil && reflect.DeepEqual(configured, msg) {
			//TODO Abdul update is not required return
			return nil
		}
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleIpamPoolUpdate: cannot dial manager")
		}
		defer conn.Close()
		out, err = c.IpamPoolUpdate(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleHostMetadataRemove")
		}
		s.policyState.configuredState.Set(msg.Id, msg)
	}
	return nil
}

// Not needed?
func (s *PolicyServer) handleIpamPoolRemove(msg *pb.IPAMPoolRemove, pending bool) error {
	s.log.Infof("Got ipam pool remove %+v, pending %v", msg, pending)
	if pending {
		s.policyState.pendingState.Set(msg.Id, msg)
	} else {
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleIpamPoolUpdate: cannot dial manager")
		}
		defer conn.Close()
		out, err = c.IpamPoolRemove(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleHostMetadataRemove")
		}
		s.policyState.configuredState.Set(msg.Id, msg)
	}
	return nil
}

func (s *PolicyServer) handleServiceAccountUpdate(msg *pb.ServiceAccountUpdate, pending bool) error {
	s.log.Infof("Got service account update %+v, pending %v", msg, pending)
	if pending {
		s.policyState.pendingState.Set(msg.Id.String(), msg)
	} else {
		configured := s.policyState.configuredState.Get(msg.Id.String())
		if configured != nil && reflect.DeepEqual(configured, msg) {
			//TODO Abdul update is not required return
			return nil
		}
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleServiceAccountUpdate: cannot dial manager")
		}
		defer conn.Close()
		out, err = c.UpdateServiceAccount(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleServiceAccountUpdate")
		}
		s.policyState.configuredState.Set(msg.Id.String(), msg)
	}

	return nil
}

func (s *PolicyServer) handleServiceAccountRemove(msg *pb.ServiceAccountRemove, pending bool) error {
	s.log.Infof("Got service account remove %+v, pending %v", msg, pending)
	if pending {
		s.policyState.pendingState.Set(msg.Id.String(), msg)
	} else {
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleServiceAccountRemove: cannot dial manager")
		}
		defer conn.Close()
		out, err = c.RemoveServiceAccount(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleServiceAccountRemove")
		}
		s.policyState.configuredState.Set(msg.Id.String(), msg)
	}

	return nil
}

func (s *PolicyServer) handleNamespaceUpdate(msg *pb.NamespaceUpdate, pending bool) error {
	s.log.Infof("Got namespace update %+v, pending %v", msg, pending)
	if pending {
		s.policyState.pendingState.Set(msg.Id.String(), msg)
	} else {
		configured := s.policyState.configuredState.Get(msg.Id.String())
		if configured != nil && reflect.DeepEqual(configured, msg) {
			//TODO Abdul update is not required return
			return nil
		}
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleNamespaceUpdate: cannot dial manager")
		}
		defer conn.Close()
		out, err = c.UpdateNamespace(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleNamespaceUpdate")
		}
		s.policyState.configuredState.Set(msg.GetId().String(), msg)
	}

	return nil
}

func (s *PolicyServer) handleNamespaceRemove(msg *pb.NamespaceRemove, pending bool) error {
	s.log.Infof("Got namespace remove %+v, pending %v", msg, pending)
	if pending {
		s.policyState.pendingState.Set(msg.Id.String(), msg)
	} else {
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleNamespaceRemove: cannot dial manager")
		}
		conn.Close()
		out, err = c.RemoveNamespace(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleNamespaceRemove")
		}
		s.policyState.configuredState.Set(msg.Id.String(), msg)
	}

	return nil
}

func (s *PolicyServer) handleRouteUpdate(msg *pb.RouteUpdate, pending bool) error {
	s.log.Infof("Got route update %+v, pending %v", msg, pending)
	id := "routeupdate" + msg.String()
	if pending {
		s.policyState.pendingState.Set(id, msg)
	} else {
		configured := s.policyState.configuredState.Get(id)
		if configured != nil && reflect.DeepEqual(configured, msg) {
			//TODO Abdul update is not required return
			return nil
		}
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleRouteUpdate: cannot dial manager")
		}
		defer conn.Close()
		out, err = c.UpdateRoute(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleRouteUpdate")
		}
		s.policyState.configuredState.Set(id, msg)
	}
	return nil
}

func (s *PolicyServer) handleRouteRemove(msg *pb.RouteRemove, pending bool) error {
	s.log.Infof("Got route remove %+v, pending %v", msg, pending)
	id := "routeremove" + msg.String()
	if pending {
		s.policyState.pendingState.Set(id, msg)
	} else {
		configured := s.policyState.configuredState.Get(id)
		if configured != nil && reflect.DeepEqual(configured, msg) {
			//TODO Abdul update is not required return
			return nil
		}
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleRouteRemove: cannot dial manager")
		}
		defer conn.Close()
		out, err = c.RemoveRoute(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleRouteRemove")
		}
		s.policyState.configuredState.Set(id, msg)
	}
	return nil
}

func (s *PolicyServer) handleVXLANTunnelEndpointUpdate(msg *pb.VXLANTunnelEndpointUpdate, pending bool) error {
	s.log.Infof("Got VXLAN tunnel endpoint update %+v, pending %v", msg, pending)
	// it does not have id fake it
	id := "vxlantunneladd-" + msg.String()
	if pending {
		s.policyState.pendingState.Set(id, msg)
	} else {
		configured := s.policyState.configuredState.Get(id)
		if configured != nil && reflect.DeepEqual(configured, msg) {
			//TODO Abdul update is not required return
			return nil
		}
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleVXLANTunnelEndpointUpdate: cannot dial manager")
		}
		defer conn.Close()
		out, err = c.UpdateVXLANTunnelEndpoint(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleVXLANTunnelEndpointUpdate")
		}
		s.policyState.configuredState.Set(id, msg)
	}

	return nil
}

func (s *PolicyServer) handleVXLANTunnelEndpointRemove(msg *pb.VXLANTunnelEndpointRemove, pending bool) error {
	s.log.Infof("Got VXLAN tunnel endpoint remove %+v, pending %v", msg, pending)
	// it does not have id fake it
	id := "vxlantunnelremove-" + msg.String()
	if pending {
		s.policyState.pendingState.Set(id, msg)
	} else {
		out := &pb.Reply{
			Successful: true,
		}
		c, conn, err := s.dialManager()
		if err != nil {
			return errors.Wrap(err, "cannot process handleVXLANTunnelEndpointRemove: cannot dial manager")
		}
		defer conn.Close()
		out, err = c.RemoveVXLANTunnelEndpoint(context.TODO(), msg)
		if err != nil || !out.Successful {
			return errors.Wrap(err, "cannot process handleVXLANTunnelEndpointRemove")
		}
		s.policyState.configuredState.Set(id, msg)
	}

	return nil
}

func (s *PolicyServer) handleWireguardEndpointUpdate(msg *pb.WireguardEndpointUpdate, pending bool) error {
	// TODO Abdul those are missing in protobuf I did not add them
	s.log.Infof("Got Wireguard endpoint update %+v, pending %v", msg, pending)
	return nil
}

func (s *PolicyServer) handleWireguardEndpointRemove(msg *pb.WireguardEndpointRemove, pending bool) error {
	// TODO Abdul those are missing in protobuf I did not add them
	s.log.Infof("Got Wireguard endpoint remove %+v, pending %v", msg, pending)
	return nil
}

func (s *PolicyServer) handleGlobalBGPConfigUpdate(msg *pb.GlobalBGPConfigUpdate, pending bool) error {
	// TODO Abdul those are missing in protobuf I did not add them
	s.log.Infof("Got GlobalBGPConfig update %+v, pending %v", msg, pending)
	return nil
}

func (s *PolicyServer) dialManager() (pb.InfraAgentClient, *grpc.ClientConn, error) {
	managerAddr := fmt.Sprintf("%s:%s", types.InfraManagerAddr, types.InfraManagerPort)
	conn, err := grpcDial(managerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		s.log.WithField("func", "dialManager")
		s.log.Errorf("unable to dial Infra Manager. err %v", err)
		return nil, nil, err
	}
	return pbNewInfraAgentClient(conn), conn, nil
}

func getCancellableListener(ctx context.Context) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(ctx, "unix", types.FelixDataplaneSocket)
}

func (s *PolicyServer) Start(t *tomb.Tomb) error {
	s.log.Info("Starting policy server")
	_ = removeSocket(types.FelixDataplaneSocket)
	waitCh := make(chan struct{})
	ctx, cancel := context.WithCancel(context.TODO())
	listener, err := cancellableListener(ctx)
	if err != nil {
		s.log.WithError(err).Errorf("Could not bind to %s", types.FelixDataplaneSocket)
		cancel()
		return err
	}
	go func() {
		defer close(waitCh)
		<-ctx.Done()
		if listener != nil {
			listener.Close()
		}
		_ = removeSocket(types.FelixDataplaneSocket)
	}()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					// error due context cancelation
					return
				default:
					s.log.WithError(err).Warn("cannot accept policy connection")
					return
				}
			}
			s.syncState = StateConnected
			go s.SyncPolicy(conn)

			s.log.Info("Waiting to close...")
			<-s.exiting
			if err = conn.Close(); err != nil {
				s.log.WithError(err).Error("error closing conection to felix API proxy")
			}
		}
	}()

	<-t.Dying()
	s.log.Info("Closing server...")
	close(s.exiting)
	cancel()
	//wait for cancel end
	<-waitCh

	s.log.Info("Policy server exited.")
	return nil
}
