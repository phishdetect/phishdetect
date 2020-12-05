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

// CheckFunction defines the functions used to implement URL or HTML checks.
type CheckFunction func(*Link, *Page, *Browser, *Brands) (bool, interface{})

// Check defines the general proprties of a CheckFunction.
type Check struct {
	Call        CheckFunction
	Score       int
	Name        string
	Description string
}

// CheckTarget is used to construct a list of targets for some checks.
// Primarily used for code deduplication.
type CheckTarget struct {
	Type       string
	Identifier string
	Content    string
}

// CheckResults contains information about check results and relevant
// matches.
type CheckResults struct {
	Entity     string      `json:"entity"`
	Identifier string      `json:"identifier"`
	Matches    interface{} `json:"matches"`
}
