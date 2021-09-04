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

package brands

// Brand defines the attributes of a brand.
type Brand struct {
	Name       string   `json:"name",yaml:"name"`             // Name of the brand.
	Original   []string `json:"original",yaml:"original"`     // List of original brand words (e.g. inclusive of products or services).
	Dangerous  []string `json:"dangerous",yaml:"dangerous"`   // List of regexps matching URLs for this brand that might be prone to abuse (e.g. Google Sites, Google Script).
	Safelist   []string `json:"safelist",yaml:"safelist"`     // List of safelisted domains associated with this brand.
	Suspicious []string `json:"suspicious",yaml:"suspicious"` // List of suspicious permutations of brand names.
	Exclusions []string `json:"exclusions",yaml:"exclusions"` // List of words to exclude from heuristics because of high risk of false positives.
	Matches    int      `json:"matches",yaml:"matches"`       // Total number of matches of analysis checks for this brand.
}
