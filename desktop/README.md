# Seku Desktop (GUI agent)

A native desktop app (Go + Fyne). On launch it asks for the **Seku username &
password** (the same account used on the web dashboard), signs in against the
server, then lets the operator run a scan **from this machine**. Every run is
attributed to the signed-in user and tagged with the device (hostname · OS/arch),
so the server's **Scan Activity** shows exactly who scanned and from where.

## Build

### Native (build on the same OS you'll run it on)
```bash
cd desktop
go mod tidy
go build -o seku-desktop .        # macOS/Linux
# Windows: go build -o seku-desktop.exe .
```
Requires a C toolchain (Fyne uses CGO): Xcode CLT on macOS, gcc + libgl1-mesa-dev
+ xorg-dev on Linux, a MinGW/MSVC toolchain on Windows.

### Cross-platform installers (recommended for distribution)
`fyne-cross` uses Docker images that carry each platform's toolchain, so you can
build signed app bundles / installers for every OS from one machine:
```bash
go install github.com/fyne-io/fyne-cross@latest
cd desktop
fyne-cross darwin  -arch=arm64,amd64 -app-id com.seku.desktop -icon Icon.png   # .app
fyne-cross windows -arch=amd64        -app-id com.seku.desktop -icon Icon.png   # .exe
fyne-cross linux   -arch=amd64        -app-id com.seku.desktop                  # tarball
```
Output lands in `fyne-cross/dist/`. (macOS/Windows still need code-signing +
notarization to avoid Gatekeeper/SmartScreen warnings — that requires the
respective developer certificates.)

## Notes
- No agent token needed — it authenticates as a normal user via `POST /api/auth/login`.
- A non-admin can only scan domains their org has verified; admins can scan any domain.
- The scan runs on the server (attributed to the user + this device). A future
  version can run the scan locally for internal-network reach.
