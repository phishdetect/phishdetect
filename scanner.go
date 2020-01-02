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
	"errors"
	"os"
	"path"
	"path/filepath"

	"github.com/hillu/go-yara"
	log "github.com/sirupsen/logrus"
)

var YaraRules *yara.Rules

func InitializeYara(yaraRulesPath string) error {
	if yaraRulesPath == "" {
		return errors.New("No Yara rules file or directory specified")
	}

	compiler, err := yara.NewCompiler()
	if err != nil {
		return err
	}
	defer compiler.Destroy()

	rulesStat, err := os.Stat(yaraRulesPath)
	if err != nil {
		log.Error(err.Error())
		return err
	}

	switch mode := rulesStat.Mode(); {
	case mode.IsDir():
		log.Debug("The specified Yara rules path is a folder, looping through files...")
		err = filepath.Walk(yaraRulesPath, func(filePath string, fileInfo os.FileInfo, err error) error {
			fileName := fileInfo.Name()

			// Check if the file has extension .yar or .yara.
			if (path.Ext(fileName) == ".yar") || (path.Ext(fileName) == ".yara") {
				log.Debug("Adding rule ", filePath)

				// Open the rule file and add it to the Yara compiler.
				rulesFile, _ := os.Open(filePath)
				defer rulesFile.Close()

				err = compiler.AddFile(rulesFile, "")
				if err != nil {
					log.Warning(err.Error())
					return nil
				}
			}
			return nil
		})
	case mode.IsRegular():
		log.Debug("Compiling Yara rule ", yaraRulesPath)

		rulesFile, _ := os.Open(yaraRulesPath)
		defer rulesFile.Close()

		err = compiler.AddFile(rulesFile, "")
		if err != nil {
			return err
		}
	}

	// Collect and compile Yara rules.
	YaraRules, err = compiler.GetRules()
	if err != nil {
		return err
	}

	return nil
}
