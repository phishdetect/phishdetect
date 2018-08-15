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

package phishdetect

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/mafredri/cdp"
	"github.com/mafredri/cdp/devtool"
	"github.com/mafredri/cdp/protocol/dom"
	"github.com/mafredri/cdp/protocol/page"
	"github.com/mafredri/cdp/rpcc"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"math/rand"
	"net"
	"strconv"
	"time"
)

// Browser is a struct containing details over a browser navigation to a URL.
type Browser struct {
	URL            string
	FinalURL       string
	Visits         []string
	HTML           string
	ScreenshotPath string
	ScreenshotData string
	UseTor         bool
	DebugPort      int
	UserAgent      string
	ContainerID    string
}

// NewBrowser instantiates a new Browser struct.
func NewBrowser(url string, screenshotPath string, useTor bool) *Browser {
	return &Browser{
		URL:            url,
		ScreenshotPath: screenshotPath,
		UseTor:         useTor,
	}
}

func (b *Browser) pickUserAgent() {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.89 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
	}

	rand.Seed(time.Now().UTC().UnixNano())
	b.UserAgent = userAgents[rand.Intn(len(userAgents))]

	log.Info("Using User-Agent: ", b.UserAgent)
}

func (b *Browser) pickDebugPort() {
	min := 9000
	max := 10000
	port := min

	rand.Seed(time.Now().UTC().UnixNano())

	// TODO: add some boundary to avoid an (unlikely) endless loop.
	for true {
		port = rand.Intn(max-min+1) + min
		conn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		conn.Close()
		break
	}

	b.DebugPort = port

	log.Info("Using debug port: ", b.DebugPort)
}

func (b *Browser) startContainer() error {
	b.pickUserAgent()
	b.pickDebugPort()

	envs := []string{fmt.Sprintf("USER_AGENT=%s", b.UserAgent)}
	if b.UseTor {
		envs = append(envs, "TOR=yes")
		log.Info("Enabled route through the Tor network")
	}

	config := &container.Config{
		Image: "phishdetect/phishdetect",
		Env:   envs,
		ExposedPorts: nat.PortSet{
			"9222/tcp": struct{}{},
		},
	}
	hostConfig := &container.HostConfig{
		PortBindings: nat.PortMap{
			"9222/tcp": []nat.PortBinding{
				{
					HostIP:   "127.0.0.1",
					HostPort: strconv.Itoa(b.DebugPort),
				},
			},
		},
		AutoRemove: true,
	}

	cli, err := client.NewEnvClient()
	if err != nil {
		return err
	}
	ctx := context.Background()

	resp, err := cli.ContainerCreate(ctx, config, hostConfig, nil, "")
	if err != nil {
		return err
	}

	b.ContainerID = resp.ID

	if err = cli.ContainerStart(ctx, b.ContainerID, types.ContainerStartOptions{}); err != nil {
		return err
	}

	log.Info("Started container with ID ", b.ContainerID)

	return nil
}

func (b *Browser) addVisit(url string) {
	for _, visit := range b.Visits {
		if visit == url {
			return
		}
	}
	b.Visits = append(b.Visits, url)
}

func (b *Browser) killContainer() error {
	cli, err := client.NewEnvClient()
	if err != nil {
		return err
	}
	ctx := context.Background()

	err = cli.ContainerKill(ctx, b.ContainerID, "")
	if err != nil {
		return err
	}

	log.Info("Killed container with ID ", b.ContainerID)

	return nil
}

// Run launches our browser and navigates to the specified URL.
func (b *Browser) Run() error {
	err := b.startContainer()
	if err != nil {
		return err
	}

	timeout := BrowserTimeout * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	devt := devtool.New(fmt.Sprintf("http://127.0.0.1:%d", b.DebugPort))

	log.Info("Attempting to connect to debug port...")

	// TODO: We need to handle this better or it will fail after the count is
	//		 over and the connection didn't succeed.
	var target *devtool.Target
	for i := 0; i < 120; i++ {
		target, err = devt.Get(ctx, devtool.Page)
		if err != nil {
			target, err = devt.Create(ctx)
			if err != nil {
				time.Sleep(500 * time.Millisecond)
				continue
			}
		}

		break
	}

	log.Info("Connection to debug port established!")

	conn, err := rpcc.DialContext(ctx, target.WebSocketDebuggerURL)
	if err != nil {
		return err
	}
	defer conn.Close()

	cli := cdp.NewClient(conn)

	domContent, err := cli.Page.DOMContentEventFired(ctx)
	if err != nil {
		return err
	}
	defer domContent.Close()

	frameNavigated, err := cli.Page.FrameNavigated(ctx)
	if err != nil {
		return err
	}
	defer frameNavigated.Close()

	requestWillBeSent, err := cli.Network.RequestWillBeSent(ctx)
	if err != nil {
		return err
	}
	defer requestWillBeSent.Close()

	if err = cli.Page.Enable(ctx); err != nil {
		return err
	}
	if err = cli.Network.Enable(ctx, nil); err != nil {
		return err
	}

	navArgs := page.NewNavigateArgs(b.URL).
		SetReferrer("https://mail.google.com/mail/u/0/")
	nav, err := cli.Page.Navigate(ctx, navArgs)
	if err != nil {
		return err
	}

	log.Debug("Started loading on frame ID ", nav.FrameID)

	// Monitor for URL visits.
	go func() {
		for true {
			select {
			case <-requestWillBeSent.Ready():
				event, err := requestWillBeSent.Recv()
				if err == nil {
					if event.Initiator.Type == "other" && *event.Type == page.ResourceTypeDocument {
						log.Debug("Network request to ", event.DocumentURL)
						b.addVisit(event.DocumentURL)
					}
				}
			case <-frameNavigated.Ready():
				event, err := frameNavigated.Recv()
				if err == nil {
					if event.Frame.ID == nav.FrameID {
						log.Debug("Browser has visited URL ", event.Frame.URL)
						b.addVisit(event.Frame.URL)
					}
				}
			}
		}
	}()

	_, err = domContent.Recv()
	if err != nil {
		log.Error(err)
	}
	log.Debug("DOMContentEventFired. Waiting for few seconds to let page finish loading...")
	time.Sleep(BrowserWaitTime * time.Second)

	// Assign FinalURL.
	if len(b.Visits) > 0 {
		b.FinalURL = b.Visits[len(b.Visits)-1]
	}

	// We get the page HTML.
	doc, err := cli.DOM.GetDocument(ctx, nil)
	if err != nil {
		return err
	}
	result, err := cli.DOM.GetOuterHTML(ctx, &dom.GetOuterHTMLArgs{
		NodeID: &doc.Root.NodeID,
	})
	if err != nil {
		return err
	}
	b.HTML = result.OuterHTML

	// We take a screenshot of the page.
	screenshotArgs := page.NewCaptureScreenshotArgs().
		SetFormat("png").
		SetQuality(80)
	screenshot, err := cli.Page.CaptureScreenshot(ctx, screenshotArgs)
	if err != nil {
		log.Warning(err)
	} else {
		b.ScreenshotData = base64.StdEncoding.EncodeToString(screenshot.Data)
		if b.ScreenshotPath != "" {
			if err = ioutil.WriteFile(b.ScreenshotPath, screenshot.Data, 0644); err != nil {
				log.Warning(err)
			} else {
				log.Info("Saved screenshot at ", b.ScreenshotPath)
			}
		}
	}

	// Now we terminate the Docker container.
	err = b.killContainer()
	if err != nil {
		log.Warning(err)
	}

	return nil
}
