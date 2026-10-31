package pull

import "github.com/warpstreamlabs/bento/public/service"

type Health struct {
	gauge  *service.MetricGauge
	log    *service.Logger
	labels []string
	down   bool
}

func NewHealth(m Metrics, log *service.Logger, source, application string) *Health {
	return &Health{gauge: m.Available, log: log, labels: []string{source, application}}
}

func (h *Health) Down(msg string) {
	h.gauge.Set(0, h.labels...)
	if !h.down {
		h.down = true
		h.log.Warn(msg)
	}
}

func (h *Health) Up() {
	h.gauge.Set(1, h.labels...)
	if h.down {
		h.down = false
		h.log.Infof("%s: available again", h.labels[1])
	}
}
