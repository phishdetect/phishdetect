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

func TestLinkParsing(t *testing.T) {
	url := "https://this.is.an.example.com:8080/path/to/file.php?arg=value&arg2=value2"

	link, err := NewLink(url)
	if err != nil {
		t.Errorf("Failed to parse URL: %s", err.Error())
	}

	if link.Scheme != "https" {
		t.Errorf("Failed to parse scheme, got \"%s\" expected \"https\"", link.Scheme)
	}

	if link.Domain != "this.is.an.example.com" {
		t.Errorf("Failed to parse domain, got \"%s\" expected \"this.is.an.example.com\"", link.Domain)
	}

	if link.Port != "8080" {
		t.Errorf("Failed to parse port, got \"%s\" expected \"8080\"", link.Port)
	}

	if link.TopDomain != "example.com" {
		t.Errorf("Failed to parse top domain, got \"%s\" expected \"example.com\"", link.TopDomain)
	}

	if link.Path != "/path/to/file.php" {
		t.Errorf("Failed to parse path, got \"%s\" expected \"/path/to/file.php\"", link.Path)
	}

	if link.RawQuery != "arg=value&arg2=value2" {
		t.Errorf("Failed to parse raw query, got \"%s\" expected \"arg=value&arg2=value2\"", link.RawQuery)
	}
}
