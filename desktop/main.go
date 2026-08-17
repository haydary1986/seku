// Seku Desktop — a GUI agent.
// On launch it asks for the Seku username/password (the same account used on the
// web dashboard), authenticates against the server, then lets the operator run a
// scan FROM this machine. Every run is attributed to the signed-in user and
// tagged with this device's info, so the server's Scan Activity shows exactly
// who scanned and from where.
//
// Build (per platform — a GUI binary can't be cross-built from a plain CI):
//
//	# native (on the same OS):
//	cd desktop && go mod tidy && go build -o seku-desktop .
//
//	# cross-platform installers via fyne-cross (uses Docker toolchains):
//	go install github.com/fyne-io/fyne-cross@latest
//	fyne-cross darwin  -arch=arm64,amd64 -app-id com.seku.desktop
//	fyne-cross windows -arch=amd64        -app-id com.seku.desktop
//	fyne-cross linux   -arch=amd64
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

type session struct {
	server string
	token  string
	user   string
}

func deviceInfo() string {
	host, _ := os.Hostname()
	if host == "" {
		host = "unknown-host"
	}
	return fmt.Sprintf("%s · %s/%s", host, runtime.GOOS, runtime.GOARCH)
}

func (s *session) post(path string, body any, auth bool) ([]byte, int, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", strings.TrimRight(s.server, "/")+path, bytes.NewReader(b))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if auth && s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	out := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, e := resp.Body.Read(buf)
		out = append(out, buf[:n]...)
		if e != nil {
			break
		}
	}
	return out, resp.StatusCode, nil
}

func main() {
	a := app.NewWithID("com.seku.desktop")
	w := a.NewWindow("Seku Desktop")
	w.Resize(fyne.NewSize(440, 460))

	s := &session{}

	// ---- Login view ----
	serverEntry := widget.NewEntry()
	serverEntry.SetText("https://sec.erticaz.com")
	userEntry := widget.NewEntry()
	userEntry.SetPlaceHolder("username")
	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("password")
	loginStatus := widget.NewLabel("")
	loginStatus.Wrapping = fyne.TextWrapWord

	loginBtn := widget.NewButton("Sign in", nil)

	// ---- Scan view (shown after login) ----
	targetEntry := widget.NewEntry()
	targetEntry.SetPlaceHolder("example.com")
	policySel := widget.NewSelect([]string{"light", "standard", "deep"}, nil)
	policySel.SetSelected("standard")
	scanStatus := widget.NewLabel("")
	scanStatus.Wrapping = fyne.TextWrapWord
	whoLabel := widget.NewLabel("")

	scanBtn := widget.NewButton("Scan this domain", nil)

	scanView := container.NewVBox(
		widget.NewLabelWithStyle("Run a scan", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		whoLabel,
		widget.NewLabel("Domain to scan"),
		targetEntry,
		widget.NewLabel("Depth"),
		policySel,
		scanBtn,
		scanStatus,
	)
	scanView.Hide()

	loginView := container.NewVBox(
		widget.NewLabelWithStyle("Sign in to Seku", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Server"),
		serverEntry,
		widget.NewLabel("Username"),
		userEntry,
		widget.NewLabel("Password"),
		passEntry,
		loginBtn,
		loginStatus,
	)

	loginBtn.OnTapped = func() {
		u := strings.TrimSpace(userEntry.Text)
		p := passEntry.Text
		if u == "" || p == "" {
			loginStatus.SetText("Enter username and password.")
			return
		}
		s.server = strings.TrimSpace(serverEntry.Text)
		loginStatus.SetText("Signing in…")
		loginBtn.Disable()
		go func() {
			body, code, err := s.post("/api/auth/login", map[string]string{"username": u, "password": p}, false)
			fyne.Do(func() {
				loginBtn.Enable()
				if err != nil {
					loginStatus.SetText("Network error: " + err.Error())
					return
				}
				if code != 200 {
					loginStatus.SetText("Sign-in failed (check credentials).")
					return
				}
				var r struct {
					Token string `json:"token"`
					User  struct {
						Username string `json:"username"`
					} `json:"user"`
				}
				if json.Unmarshal(body, &r) != nil || r.Token == "" {
					loginStatus.SetText("Unexpected server response.")
					return
				}
				s.token = r.Token
				s.user = r.User.Username
				if s.user == "" {
					s.user = u
				}
				whoLabel.SetText(fmt.Sprintf("Signed in as %s · %s", s.user, deviceInfo()))
				loginView.Hide()
				scanView.Show()
			})
		}()
	}

	scanBtn.OnTapped = func() {
		t := strings.TrimSpace(targetEntry.Text)
		if !strings.Contains(t, ".") {
			scanStatus.SetText("Enter a valid domain.")
			return
		}
		url := t
		if !strings.HasPrefix(url, "http") {
			url = "https://" + url
		}
		scanBtn.Disable()
		scanStatus.SetText("Creating target…")
		go func() {
			// 1) create a hidden ad-hoc target
			tb, tc, terr := s.post("/api/targets", map[string]any{"url": url, "name": url, "adhoc": true}, true)
			if terr != nil || (tc != 200 && tc != 201) {
				fyne.Do(func() { scanBtn.Enable(); scanStatus.SetText("Could not create target (are you authorized for this domain?).") })
				return
			}
			var tgt struct {
				ID  uint `json:"ID"`
				ID2 uint `json:"id"`
			}
			json.Unmarshal(tb, &tgt)
			tid := tgt.ID
			if tid == 0 {
				tid = tgt.ID2
			}
			// 2) start the scan, attributed to this user + device
			fyne.Do(func() { scanStatus.SetText("Starting scan…") })
			payload := map[string]any{
				"target_ids":  []uint{tid},
				"policy":      policySel.Selected,
				"authorized":  true,
				"source":      "desktop",
				"device_info": deviceInfo(),
			}
			_, sc, serr := s.post("/api/scans/start", payload, true)
			fyne.Do(func() {
				scanBtn.Enable()
				if serr != nil {
					scanStatus.SetText("Network error: " + serr.Error())
					return
				}
				switch sc {
				case 200, 201:
					scanStatus.SetText("Scan started ✔  — it is logged in the dashboard under your name (" + s.user + ") and this device. Open the web dashboard to watch progress and see the report.")
				case 402:
					scanStatus.SetText("Deep scan requires payment. Choose light/standard or buy a credit.")
				case 403:
					scanStatus.SetText("Not authorized for this domain (verify ownership first).")
				default:
					scanStatus.SetText(fmt.Sprintf("Server returned %d.", sc))
				}
			})
		}()
	}

	w.SetContent(container.NewVBox(loginView, scanView))
	w.ShowAndRun()
}
