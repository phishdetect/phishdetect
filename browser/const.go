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

package browser

import (
	"time"
)

// BrowserWaitTime is the seconds we will wait before fetching navigation results.
const BrowserWaitTime time.Duration = 5

// BrowserEventWaitTime is the seconds we wait while attempting to fetch some
// events from DevTools, before failing.
const BrowserEventWaitTime time.Duration = 15

// BrowserTimeout is the minutes we will wait before declaring failed the
// connection to our debugged browser or to the URL failed.
const BrowserTimeout time.Duration = 1

// TorSocksProxy defines the default SOCKS5 conection string for Tor.
const TorSocksProxy string = "socks5://127.0.0.1:9050"
