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

package brand

// Brand defines the attributes of a brand.
type Brand struct {
	Name       string   `json:"name",yaml:"name"`
	Original   []string `json:"original",yaml:"original"`
	Dangerous  []string `json:"dangerous",yaml:"dangerous"`
	Safelist   []string `json:"safelist",yaml:"safelist"`
	Suspicious []string `json:"suspicious",yaml:"suspicious"`
	Matches    int      `json:"matches",yaml:"matches"`
}
