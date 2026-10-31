package pull

import "github.com/warpstreamlabs/bento/public/service"

type Metrics struct {
	Emitted   *service.MetricCounter
	Late      *service.MetricCounter
	Skipped   *service.MetricCounter
	Errors    *service.MetricCounter
	Lag       *service.MetricGauge
	Lateness  *service.MetricTimer
	Available *service.MetricGauge
}

func NewMetrics(m *service.Metrics) Metrics {
	return Metrics{
		Emitted:   m.NewCounter("collector_events_emitted", "source", "application"),
		Late:      m.NewCounter("collector_events_late", "source", "application"),
		Skipped:   m.NewCounter("collector_events_malformed", "source", "application"),
		Errors:    m.NewCounter("collector_poll_errors", "source", "application"),
		Lag:       m.NewGauge("collector_cursor_lag_seconds", "source", "application"),
		Lateness:  m.NewTimer("collector_event_lateness", "source", "application"),
		Available: m.NewGauge("collector_application_available", "source", "application"),
	}
}
