// PhishDetect
// Copyright (c) 2018-2020 Claudio Guarnieri.
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

func TestPage(t *testing.T) {
	html := `<html>
<head>
<title>Google Sign-In</title>
</head>
<body>
<form method="POST" action="form.php">
	<input type="password" name="password" />
	<input type="hidden" name="hidden" value="hidden" />
	<input type="submit" value="Login" />
</form>
</body>
</html>`

	page, err := NewPage(html, []Resource{})
	if err != nil {
		t.Errorf("Failed to parse HTML: %s", err.Error())
	}

	title := page.GetTitle()
	if title != "Google Sign-In" {
		t.Errorf("Failed to parse page title, got \"%s\" expected \"Google Sign-In\"", title)
	}

	passwordInputs := page.GetInputs("password")
	if len(passwordInputs) != 1 {
		t.Errorf("Failed to parse password inputs, got \"%d\" expected 1", len(passwordInputs))
	}
}
