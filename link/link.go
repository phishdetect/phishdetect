// PhishDetect
// Copyright (c) 2018-2021 Claudio Guarnieri.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package link

import (
	"errors"
	"net"
	"strings"

	"github.com/bobesa/go-domain-util/domainutil"
	"github.com/goware/urlx"
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

// New instantiates a Link struct.
func New(urlString string) (*Link, error) {
	parsed, err := urlx.Parse(urlString)
	if err != nil {
		return nil, err
	}

	// NOTE: This is an ugly hack to work around the scheme enforcement of urls.
	// We don't want to have it enforced and leave it empty if it is not there.
	// This is normally for our check for TLS in the link.
	scheme := parsed.Scheme
	if scheme == "http" && !strings.HasPrefix(urlString, "http") {
		scheme = ""
	}

	// We separate hostname from port number.
	host := parsed.Host
	if host == "" {
		return nil, errors.New("The link does not contain a host")
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
