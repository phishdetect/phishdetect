// PhishDetect
// Copyright (C) 2018  Claudio Guarnieri
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

package main

import (
	"net/http"
	"encoding/json"

	log "github.com/sirupsen/logrus"
)

type Indicators struct {
	Senders []string `json:"senders"`
	Domains []string `json:"domains"`
}

func apiIndicatorsFetch(w http.ResponseWriter, r *http.Request) {
	log.Debug("Received request to fetch indicators")

	indicators := Indicators{
		Senders: []string{"0AD6FDDB0A6CDE372FD895DB5E1B97B1EF986BE414C6890C5D7089EE80399B1E"},
		Domains: []string{"5D977F4D473900F405E5319857534A57F2D4F00630029949B458FB149F08069C"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(indicators)
}
