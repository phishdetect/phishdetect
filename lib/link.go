package phishdetect

import (
	"errors"
	"github.com/bobesa/go-domain-util/domainutil"
	"github.com/goware/urlx"
	log "github.com/sirupsen/logrus"
	"net"
	"strings"
)

// Link defines details of a parsed URL.
type Link struct {
	URL        string
	Scheme     string
	Domain     string
	Port       string
	TopDomain  string
	Path       string
	RawQuery   string
	Parameters map[string]string
}

// NewLink instantiates a Link struct.
func NewLink(urlString string) (*Link, error) {
	parsed, err := urlx.Parse(urlString)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	// NOTE: This is an ugly hack to work around the scheme enforcement of urlx.
	// We don't want to have it enforced and leave it empty if it is not there.
	// This is normally for our check for TLS in the link.
	scheme := parsed.Scheme
	if scheme == "http" && !strings.HasPrefix(urlString, "http") {
		scheme = ""
	}

	// We separate hostname from port number.
	host := parsed.Host
	if host == "" {
		return nil, errors.New("The link does not contain a host.")
	}

	port := ""
	if strings.Contains(parsed.Host, ":") {
		host, port, _ = net.SplitHostPort(parsed.Host)
	}

	// We parse RawQuery parameters and create a map.
	params := make(map[string]string)
	for _, param := range strings.Split(parsed.RawQuery, "&") {
		key := ""
		value := ""
		if strings.Contains(param, "=") {
			fields := strings.SplitN(param, "=", 2)
			key = fields[0]
			value = fields[1]
		} else {
			key = param
		}

		params[key] = value
	}

	return &Link{
		URL:        urlString,
		Scheme:     scheme,
		Domain:     host,
		Port:       port,
		TopDomain:  domainutil.Domain(host),
		Path:       parsed.Path,
		RawQuery:   parsed.RawQuery,
		Parameters: params,
	}, nil
}
