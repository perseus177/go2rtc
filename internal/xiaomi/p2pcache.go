package xiaomi

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/AlexxIT/go2rtc/internal/app"
)

// Every connection to a Xiaomi camera starts with a cloud call: the cloud
// hands out the device's P2P id and signs our client key, and the device lets
// in only a client whose key carries that signature. The video itself then
// flows over the LAN. So while the cloud is unreachable the camera is as good
// as gone -- unless the last credentials it issued are kept.
//
// Measured on an IMILAB EC2 gateway: the signature is not single-use. The
// same client key and signature opened the camera again two minutes later
// without any cloud call. What ends their life is the device rotating its own
// key (`device_public`), after which the cloud must sign again. The device
// key was seen unchanged for at least 48 minutes and changed between days.
// Hence this cache is a bridge over an internet outage, not a replacement
// for the cloud, and the log says how old the credentials being reused are.
//
// The cache is written next to the config file so it survives a restart,
// which is when it is needed most: a power cut tends to take the internet
// connection down with it. It holds the client's private key and the cloud's
// signature, the same sensitivity as the account token in the config, and is
// kept owner-readable only.

type p2pCreds struct {
	Query map[string]string `json:"query"`
	// When the cloud issued these credentials.
	IssuedAt time.Time `json:"issued_at"`
	// Since when the device has presented this `device_public`. Carried over
	// from the previous credentials when the key did not change, so that a
	// key change can be logged with how long the previous key was in use.
	KeySince time.Time `json:"key_since"`
}

// Query parameters that getLegacyURL and getMissURL fill in from the cloud.
var p2pKeys = []string{
	"uid", "client_public", "client_private", "device_public", "sign", "password", "vendor",
}

var (
	p2pCache   = map[string]*p2pCreds{} // by did
	p2pCacheMu sync.Mutex
)

func p2pCachePath() string {
	if app.ConfigPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(app.ConfigPath), "xiaomi_p2p_cache.json")
}

func loadP2PCache() {
	path := p2pCachePath()
	if path == "" {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var saved map[string]*p2pCreds
	if err = json.Unmarshal(b, &saved); err != nil {
		log.Warn().Err(err).Msgf("xiaomi: ignoring unreadable P2P cache %s", path)
		return
	}
	p2pCacheMu.Lock()
	for did, creds := range saved {
		if creds != nil && len(creds.Query) > 0 {
			p2pCache[did] = creds
		}
	}
	n := len(p2pCache)
	p2pCacheMu.Unlock()
	if n > 0 {
		log.Info().Msgf("xiaomi: loaded P2P credentials for %d device(s) from %s", n, path)
	}
}

func saveP2PCache() {
	path := p2pCachePath()
	if path == "" {
		return
	}
	p2pCacheMu.Lock()
	b, err := json.MarshalIndent(p2pCache, "", "  ")
	p2pCacheMu.Unlock()
	if err != nil {
		return
	}
	if err = os.WriteFile(path, b, 0o600); err != nil {
		log.Warn().Err(err).Msgf("xiaomi: can't write P2P cache %s", path)
	}
}

// rememberP2P keeps the credentials in the URL the cloud just helped build.
func rememberP2P(did, rawURL string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	query := u.Query()
	creds := &p2pCreds{Query: map[string]string{}}
	for _, key := range p2pKeys {
		if value := query.Get(key); value != "" {
			creds.Query[key] = value
		}
	}
	if creds.Query["sign"] == "" && creds.Query["password"] == "" {
		return // nothing the device would accept
	}

	now := time.Now()
	creds.IssuedAt = now
	creds.KeySince = now

	p2pCacheMu.Lock()
	prev := p2pCache[did]
	if prev != nil {
		if prev.Query["device_public"] == creds.Query["device_public"] {
			creds.KeySince = prev.KeySince
		} else {
			// Logged here because this is the only place that sees both
			// keys; whoever reads the log learns how long a key lasts.
			log.Info().Msgf(
				"xiaomi: did=%s device key changed, the previous one was in use for %s",
				did, now.Sub(prev.KeySince).Round(time.Second),
			)
		}
	}
	p2pCache[did] = creds
	p2pCacheMu.Unlock()

	saveP2PCache()
}

// cachedP2PURL rebuilds the dial URL for a device from the last credentials
// the cloud issued for it. The bool is false when none are known.
func cachedP2PURL(u *url.URL, did string) (string, time.Duration, bool) {
	p2pCacheMu.Lock()
	creds := p2pCache[did]
	p2pCacheMu.Unlock()
	if creds == nil {
		return "", 0, false
	}
	query := u.Query()
	for key, value := range creds.Query {
		query.Set(key, value)
	}
	cached := *u
	cached.RawQuery = query.Encode()
	return cached.String(), time.Since(creds.IssuedAt), true
}
