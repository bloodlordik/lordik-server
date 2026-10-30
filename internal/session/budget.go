package session

import (
	"errors"
	"math"

	"github.com/telegramdesktop/tproxy-server/internal/config"
	"github.com/telegramdesktop/tproxy-server/internal/frame"
)

const (
	queueItemCost                = 256
	controlReserveExtraItems     = 16
	controlReserveItemsPerStream = 3
)

type pendingClass byte

const (
	pendingUplink pendingClass = iota
	pendingDownlink
	pendingControl
)

func ValidateBudget(cfg config.Config) error {
	reserveCost, reserveItems := pendingControlReserve(cfg.Limits)
	sessions := cfg.Limits.MaxSessionsGlobal
	if reserveCost > cfg.Limits.MaxPendingGlobal/sessions {
		return errors.New("per-session control reserve times max_sessions_global exhausts max_pending_global")
	}
	if reserveItems > cfg.Limits.MaxPendingItemsGlobal/sessions {
		return errors.New("per-session control reserve times max_sessions_global exhausts max_pending_items_global")
	}
	return nil
}

func pendingControlReserve(limits config.Limits) (int, int) {
	items := controlReserveExtraItems
	if limits.MaxStreamsPerSession > (math.MaxInt-items)/controlReserveItemsPerStream {
		return limits.MaxPendingPerSession, limits.MaxPendingItemsPerSession
	}
	items += limits.MaxStreamsPerSession * controlReserveItemsPerStream
	costPerItem := queueItemCost + frame.HeaderSize + 4
	if items > math.MaxInt/costPerItem {
		return limits.MaxPendingPerSession, limits.MaxPendingItemsPerSession
	}
	return items * costPerItem, items
}

func pendingUplinkReserve(limits config.Limits) (int, int) {
	items := limits.MaxBodyBytes / frame.HeaderSize
	if items > frame.MaxBatchFrames {
		items = frame.MaxBatchFrames
	}
	if items > (math.MaxInt-limits.MaxBodyBytes)/queueItemCost {
		return limits.MaxPendingPerSession, limits.MaxPendingItemsPerSession
	}
	return limits.MaxBodyBytes + items*queueItemCost, items
}

func subtractPendingReserve(
	cost, items int,
	reserveCost, reserveItems int) (int, int) {
	if reserveCost >= cost {
		cost = 0
	} else {
		cost -= reserveCost
	}
	if reserveItems >= items {
		items = 0
	} else {
		items -= reserveItems
	}
	return cost, items
}

func (s *Session) uplinkPendingLimits() (int, int) {
	reserveCost, reserveItems := pendingControlReserve(s.limits)
	return subtractPendingReserve(
		s.limits.MaxPendingPerSession,
		s.limits.MaxPendingItemsPerSession,
		reserveCost,
		reserveItems)
}

func (s *Session) downlinkPendingLimits() (int, int) {
	cost, items := s.uplinkPendingLimits()
	reserveCost, reserveItems := pendingUplinkReserve(s.limits)
	return subtractPendingReserve(
		cost,
		items,
		reserveCost,
		reserveItems)
}

func (s *Session) dataFrameAllowanceLocked(limit int) int {
	costLimit, itemLimit := s.downlinkPendingLimits()
	if s.pendingItems >= itemLimit {
		return 0
	}
	available := costLimit - s.pendingCost - queueItemCost - frame.HeaderSize
	if available <= 0 {
		return 0
	}
	if limit > available {
		limit = available
	}
	return limit
}

func (s *Session) reservePendingLocked(
	cost, items int,
	class pendingClass) bool {
	costLimit := s.limits.MaxPendingPerSession
	itemLimit := s.limits.MaxPendingItemsPerSession
	if class == pendingUplink {
		costLimit, itemLimit = s.uplinkPendingLimits()
	} else if class == pendingDownlink {
		costLimit, itemLimit = s.downlinkPendingLimits()
	}
	if cost <= 0 || items < 0 || cost > costLimit || items > itemLimit || s.pendingCost > costLimit-cost || s.pendingItems > itemLimit-items {
		return false
	}
	if s.budget != nil && !s.budget(cost, items, class) {
		return false
	}
	s.pendingCost += cost
	s.pendingItems += items
	return true
}

func (s *Session) releasePendingLocked(cost, items int) {
	if cost == 0 && items == 0 {
		return
	}
	if cost < 0 || items < 0 || cost > s.pendingCost || items > s.pendingItems {
		panic("invalid session pending budget release")
	}
	s.pendingCost -= cost
	s.pendingItems -= items
	if s.budget != nil {
		s.budget(-cost, -items, pendingUplink)
	}
	close(s.budgetNotify)
	s.budgetNotify = make(chan struct{})
}

func (s *Session) backendWriteReservationLocked(
	values []frame.Frame) (int, int) {
	live := make(map[uint32]bool, len(s.streams))
	for id := range s.streams {
		live[id] = true
	}
	cost := 0
	items := 0
	for _, value := range values {
		if value.StreamID == 0 {
			continue
		}
		switch value.Type {
		case frame.Open:
			live[value.StreamID] = true
		case frame.Data:
			if live[value.StreamID] {
				cost += len(value.Payload) + queueItemCost
				items++
			}
		case frame.Close:
			delete(live, value.StreamID)
		}
	}
	return cost, items
}
