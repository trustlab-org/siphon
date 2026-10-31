package fakegws

import (
	"fmt"
	"math/rand"
	"strconv"
	"time"

	reports "google.golang.org/api/admin/reports/v1"
)

// Synth generates realistic-looking Workspace activities; IPs come from documentation ranges.
type Synth struct {
	rng      *rand.Rand
	customer string
	domain   string
	users    []string
}

func NewSynth(seed int64, domain string, users int) *Synth {
	g := &Synth{rng: rand.New(rand.NewSource(seed)), customer: "C0fake01", domain: domain}
	for i := range users {
		g.users = append(g.users, fmt.Sprintf("user%03d@%s", i, domain))
	}
	return g
}

func (g *Synth) Activity(app string, at time.Time) *reports.Activity {
	user := g.pick(g.users...)
	a := &reports.Activity{
		Kind: "admin#reports#activity",
		Id: &reports.ActivityId{
			ApplicationName: app,
			CustomerId:      g.customer,
			Time:            at.UTC().Format(time.RFC3339Nano),
			UniqueQualifier: g.rng.Int63(),
		},
		Actor:     &reports.ActivityActor{CallerType: "USER", Email: user, ProfileId: strconv.FormatInt(100000000000000000+g.rng.Int63n(1e9), 10)},
		IpAddress: g.ip(),
	}
	switch app {
	case "login":
		a.Events = g.login()
	case "token":
		a.Events = g.token()
	case "drive":
		a.Events = g.drive(user)
	case "admin":
		a.Events = g.admin()
	case "user_accounts":
		a.Events = g.userAccounts()
	default:
		a.Events = []*reports.ActivityEvents{{Type: "activity", Name: "synthetic_event"}}
	}
	return a
}

func (g *Synth) login() []*reports.ActivityEvents {
	suspicious := g.rng.Float64() < 0.03
	params := []*reports.ActivityEventsParameters{
		{Name: "login_type", Value: "google_password"},
		{Name: "is_suspicious", BoolValue: suspicious, ForceSendFields: []string{"BoolValue"}},
	}
	switch r := g.rng.Float64(); {
	case r < 0.75:
		return []*reports.ActivityEvents{
			{Type: "login", Name: "login_success", Parameters: params},
			{Type: "login", Name: "login_verification", Parameters: []*reports.ActivityEventsParameters{{Name: "login_challenge_method", MultiValue: []string{"idv_preregistered_phone"}}}},
		}
	case r < 0.95:
		return []*reports.ActivityEvents{{Type: "login", Name: "login_failure", Parameters: append(params,
			&reports.ActivityEventsParameters{Name: "login_failure_type", Value: "login_failure_invalid_password"})}}
	default:
		return []*reports.ActivityEvents{{Type: "login", Name: "logout", Parameters: params[:1]}}
	}
}

func (g *Synth) token() []*reports.ActivityEvents {
	app := g.pick("Grammarly", "Zoom", "Notion", "Quizlet", "PDF Converter Pro", "Unknown Calendar Sync")
	return []*reports.ActivityEvents{{Type: "auth", Name: g.pick("authorize", "authorize", "request", "revoke"), Parameters: []*reports.ActivityEventsParameters{
		{Name: "app_name", Value: app},
		{Name: "client_id", Value: strconv.FormatInt(g.rng.Int63n(1e12), 10) + ".apps.googleusercontent.com"},
		{Name: "client_type", Value: "WEB"},
		{Name: "scope", MultiValue: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			g.pick("https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/calendar"),
		}},
	}}}
}

func (g *Synth) drive(user string) []*reports.ActivityEvents {
	doc := []*reports.ActivityEventsParameters{
		{Name: "doc_id", Value: strconv.FormatInt(g.rng.Int63(), 36)},
		{Name: "doc_title", Value: g.pick("Exam paper draft", "Lab report", "Fee receipts 2026", "Research data", "Timetable")},
		{Name: "doc_type", Value: g.pick("document", "spreadsheet", "pdf", "presentation")},
		{Name: "owner", Value: user},
		{Name: "visibility", Value: g.pick("private", "shared_internally", "people_with_link", "public_on_the_web")},
	}
	name := g.pick("view", "view", "view", "edit", "download", "change_user_access")
	events := []*reports.ActivityEvents{{Type: "access", Name: name, Parameters: doc}}
	if name == "change_user_access" {
		events[0].Type = "acl_change"
		events = append(events, &reports.ActivityEvents{Type: "acl_change", Name: "change_document_visibility", Parameters: doc})
	}
	return events
}

func (g *Synth) admin() []*reports.ActivityEvents {
	name := g.pick("CHANGE_PASSWORD", "SUSPEND_USER", "GRANT_ADMIN_PRIVILEGE", "CREATE_EMAIL_MONITOR")
	return []*reports.ActivityEvents{{Type: "USER_SETTINGS", Name: name, Parameters: []*reports.ActivityEventsParameters{
		{Name: "USER_EMAIL", Value: g.pick(g.users...)},
		{Name: "ROLE_NAME", Value: g.pick("_SEED_ADMIN_ROLE", "Help Desk Admin", "User Management Admin")},
	}}}
}

func (g *Synth) userAccounts() []*reports.ActivityEvents {
	name := g.pick("password_edit", "2sv_enroll", "2sv_disable", "recovery_email_edit", "recovery_phone_edit")
	return []*reports.ActivityEvents{{Type: "account", Name: name}}
}

func (g *Synth) ip() string {
	if g.rng.Float64() < 0.1 {
		return fmt.Sprintf("198.51.100.%d", g.rng.Intn(254)+1)
	}
	return fmt.Sprintf("203.0.113.%d", g.rng.Intn(254)+1)
}

func (g *Synth) pick(options ...string) string {
	return options[g.rng.Intn(len(options))]
}
