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

package phishdetect

import (
	"testing"
)

func TestNormalizeURL(t *testing.T) {
	url := "example.com"
	normalized := NormalizeURL(url)

	if normalized != "http://example.com" {
		t.Errorf("Normalizing URL scheme failed, expected \"http://example.com\" got \"%s\"", normalized)
	}

	url = "https://example.com"
	normalized = NormalizeURL(url)

	if normalized != url {
		t.Errorf("Normalizing correct URL failed, expected \"%s\" got \"%s\"", url, normalized)
	}
}
