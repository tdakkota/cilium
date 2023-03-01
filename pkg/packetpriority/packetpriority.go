package packetpriority

import (
	"fmt"
	"math"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/qosmap"
	"github.com/cilium/cilium/pkg/option"
)

const (
	subsystem = "priority-manager"

	// EgressPriority is the K8s Pod annotation.
	EgressPriority = "network.cilium.io/packet-qos"

	top = 15
	low = 6
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsystem)

var nameToValue = map[string]uint32{
	"top": top,
	"low": low,
}

func GetPriorityValue(priority string) (uint32, error) {
	val, ok := nameToValue[priority]
	if !ok {
		return 0, fmt.Errorf("unknown priority %q", priority)
	}
	return val, nil
}

func InitPriorityManager() {
	if option.Config.DryMode || !option.Config.EnablePriorityManager {
		return
	}

	if len(option.Config.GetDevices()) == 0 {
		log.Warn("BPF packet priority manager could not detect host devices. Disabling the feature.")
		option.Config.EnablePriorityManager = false
		return
	}

	log.Info("Setting up BPF priority manager")

	if _, err := qosmap.PriorityMap().OpenOrCreate(); err != nil {
		log.WithError(err).Fatal("Failed to access PriorityMap")
	}

	for _, device := range option.Config.GetDevices() {
		link, err := netlink.LinkByName(device)
		if err != nil {
			log.WithError(err).WithField("device", device).Warn("Link does not exist")
			continue
		}

		hardwareQueues := link.Attrs().NumTxQueues
		const (
			topRatio = 7
			lowRatio = 1
		)
		if hardwareQueues < topRatio+lowRatio {
			log.WithField("device", device).Warnf("Too few Tx queues %d < %d+%d",
				hardwareQueues, topRatio, lowRatio)
			continue
		}
		one := float64(hardwareQueues) / float64(topRatio+lowRatio)
		lowQueues := uint16(math.Ceil(lowRatio * one))
		topQueues := uint16(hardwareQueues) - lowQueues

		// We strictly want to avoid a down/up cycle on the device at
		// runtime, so given we've changed the default qdisc to FQ, we
		// need to reset the root qdisc, and then set up MQ which will
		// automatically get FQ leaf qdiscs (given it's been default).
		qdisc := &netlink.GenericQdisc{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_ROOT,
			},
			QdiscType: "noqueue",
		}
		if err := netlink.QdiscReplace(qdisc); err != nil {
			log.WithError(err).WithField("device", device).
				Fatalf("Cannot replace root Qdisc to %s", qdisc.QdiscType)
		}

		// traffic class 0 — high priority traffic
		// traffic class 1 — low priority traffic

		// Set all priorities mapping to 1, except for top.
		var prioMap [16]uint8
		for i := range prioMap {
			prioMap[i] = 1
		}
		prioMap[top] = 0

		opt := nl.TcMqPrioQopt{
			NumTc:     2, // two traffic classes (low, top)
			PrioTcMap: prioMap,
			Hw:        0, // FIXME(tdakkota): no hardware QoS?
			Count: [16]uint16{
				0: topQueues,
				1: lowQueues,
			},
			Offset: [16]uint16{
				0: 0,
				1: topQueues,
			},
		}

		prio := &netlink.MqPrio{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_ROOT,
			},
			Opt: opt,
		}
		if err := netlink.QdiscReplace(prio); err != nil {
			log.WithError(err).WithField("device", device).
				Fatalf("Cannot replace root Qdisc to %s", qdisc.QdiscType)
		}
	}
}
