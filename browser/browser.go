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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"time"

	"github.com/botherder/go-savetime/hashes"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	networkTypes "github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/mafredri/cdp"
	"github.com/mafredri/cdp/devtool"
	"github.com/mafredri/cdp/protocol/dom"
	"github.com/mafredri/cdp/protocol/network"
	"github.com/mafredri/cdp/protocol/page"
	"github.com/mafredri/cdp/rpcc"
	log "github.com/sirupsen/logrus"
)

// RequestResponse contains the combination of an HTTP request and its relevant
// response. It should only be used to mark resources loaded by single visits.
type RequestResponse struct {
	Request  *network.RequestWillBeSentReply `json:"request"`
	Response *network.ResponseReceivedReply  `json:"response"`
}

// Visit identifies actually documents loaded on the browser frame.
type Visit struct {
	VisitID   string                            `json:"visit_id"`
	Requests  []*network.RequestWillBeSentReply `json:"requests"`
	Response  *network.ResponseReceivedReply    `json:"response"`
	Resources []RequestResponse                 `json:"resources"`
	Error     *network.LoadingFailedReply       `json:"error"`
}

// ByChronologicalOrder is used to order requests by timestamp.
type ByChronologicalOrder []*network.RequestWillBeSentReply

func (r ByChronologicalOrder) Len() int {
	return len(r)
}
func (r ByChronologicalOrder) Less(i, j int) bool {
	return r[i].Timestamp < r[j].Timestamp
}
func (r ByChronologicalOrder) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

// ResourceDataEntry contains metadata information on downloaded resource files
// such as JavaScript snippets.
type ResourceDataEntry struct {
	VisitID   string `json:"visit_id"`
	RequestID string `json:"request_id"`
	Type      string `json:"type"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Content   string `json:"content"`
}

// ResourcesData is a collection of ResourceDataEntry items.
type ResourcesData []ResourceDataEntry

// Download contains details of files which were offered for download.
type Download struct {
	URL      string `json:"url"`
	FileName string `json:"file_name"`
}

// Dialog contains details of JavaScript dialogs opened.
type Dialog struct {
	URL     string `json:"url"`
	Type    string `json:"type"`
	Message string `json:"message"`
}

// NavigationHistory is a list of NavigationEntry from DevTools.
type NavigationHistory []page.NavigationEntry

// Browser is a struct containing details over a browser navigation to a URL.
type Browser struct {
	UseTor            bool                              `json:"use_tor"`
	DebugPort         int                               `json:"debug_port"`
	DebugURL          string                            `json:"debug_url"`
	LogEvents         bool                              `json:"log_events"`
	UserAgent         string                            `json:"user_agent"`
	ImageName         string                            `json:"image_name"`
	NetworkID         string                            `json:"network_id"`
	ContainerID       string                            `json:"container_id"`
	FrameID           string                            `json:"frame_id"`
	URL               string                            `json:"url"`
	FinalURL          string                            `json:"final_url"`
	RequestEvents     []*network.RequestWillBeSentReply `json:"request_events"`
	ResponseEvents    []*network.ResponseReceivedReply  `json:"response_events"`
	ErrorEvents       []*network.LoadingFailedReply     `json:"error_events"`
	Visits            []Visit                           `json:"visits"`
	ResourcesData     ResourcesData                     `json:"resources_data"`
	Downloads         []Download                        `json:"downloads"`
	NavigationHistory NavigationHistory                 `json:"navigation_history"`
	Dialogs           []Dialog                          `json:"dialogs"`
	HTML              string                            `json:"html"`
	HTMLSHA256        string                            `json:"html_sha256"`
	ScreenshotPath    string                            `json:"screenshot_path"`
	ScreenshotData    string                            `json:"screenshot_data"`
}

// LogCodec captures the output from writing RPC requests and reading
// responses on the connection. It implements rpcc.Codec via
// WriteRequest and ReadResponse.
// Adapted from: https://pkg.go.dev/github.com/mafredri/cdp#example-package-Logging
type LogCodec struct{ conn io.ReadWriter }

// WriteRequest marshals v into a buffer, writes its contents onto the
// connection and logs it.
func (c *LogCodec) WriteRequest(req *rpcc.Request) error {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetIndent("", "\t")
	if err := encoder.Encode(req); err != nil {
		return err
	}
	log.Debug("DevTools Debug SEND:\n", buf.String())
	_, err := c.conn.Write(buf.Bytes())
	if err != nil {
		return err
	}
	return nil
}

// ReadResponse unmarshals from the connection into v whilst echoing
// what is read into a buffer for logging.
func (c *LogCodec) ReadResponse(resp *rpcc.Response) error {
	var buf bytes.Buffer
	if err := json.NewDecoder(io.TeeReader(c.conn, &buf)).Decode(resp); err != nil {
		return err
	}
	var bufIndented bytes.Buffer
	json.Indent(&bufIndented, buf.Bytes(), "", "\t")
	log.Debug("DevTools Debug RECV:\n", bufIndented.String())
	return nil
}

// New instantiates a new Browser struct.
func New(url string, screenshotPath string, useTor bool, logEvents bool, imageName string) *Browser {
	if imageName == "" {
		imageName = "phishdetect/phishdetect"
	}

	return &Browser{
		URL:            url,
		ScreenshotPath: screenshotPath,
		UseTor:         useTor,
		ImageName:      imageName,
		LogEvents:      logEvents,
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

	log.Debug("Using User-Agent: ", b.UserAgent)
}

func (b *Browser) pickDebugPort() {
	min := 9000
	max := 60000
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

	log.Debug("Using debug port: ", b.DebugPort)
}

func (b *Browser) createNetwork() error {
	options := types.NetworkCreate{
		CheckDuplicate: true,
		Driver:         "bridge",
		EnableIPv6:     false,
		Internal:       true,
	}

	cli, err := client.NewEnvClient()
	if err != nil {
		return err
	}
	defer cli.Close()

	ctx := context.Background()

	networkName := fmt.Sprintf("pdnet-%s", b.ContainerID)
	resp, err := cli.NetworkCreate(ctx, networkName, options)
	if err != nil {
		return err
	}

	if resp.Warning != "" {
		log.Warning(resp.Warning)
	}

	b.NetworkID = resp.ID

	log.Debug("Created a new Docker network with identifier: ", b.NetworkID)

	return cli.NetworkConnect(ctx, b.NetworkID, b.ContainerID, &networkTypes.EndpointSettings{})
}

func (b* Browser) destroyNetwork() error {
	if b.NetworkID == "" {
		return nil
	}

	cli, err := client.NewEnvClient()
	if err != nil {
		return err
	}
	defer cli.Close()

	ctx := context.Background()

	inspect, err := cli.NetworkInspect(ctx, b.NetworkID, types.NetworkInspectOptions{})
	if err != nil {
		return err
	}

	for container, _ := range inspect.Containers {
		if err := cli.NetworkDisconnect(ctx, b.NetworkID, container, true); err != nil {
			return fmt.Errorf("Unable to disconnect container %s from network %s: %s",
				container, b.NetworkID, err)
		}
	}

	return cli.NetworkRemove(ctx, b.NetworkID)
}

func (b *Browser) startContainer() error {
	b.pickUserAgent()
	b.pickDebugPort()

	envs := []string{fmt.Sprintf("USER_AGENT=%s", b.UserAgent)}
	if b.UseTor {
		envs = append(envs, "TOR=yes")
		log.Debug("Enabled route through the Tor network")
	}

	config := &container.Config{
		Image: b.ImageName,
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
		return fmt.Errorf("Unable to create new Docker client: %s", err)
	}
	defer cli.Close()

	ctx := context.Background()

	resp, err := cli.ContainerCreate(ctx, config, hostConfig, nil, nil, "")
	if err != nil {
		return fmt.Errorf("Unable to create container: %s", err)
	}

	b.ContainerID = resp.ID

	err = b.createNetwork()
	if err != nil {
		return fmt.Errorf("Unable to create new Docker network: %s", err)
	}

	if err = cli.ContainerStart(ctx, b.ContainerID, types.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("Unable to start container: %s", err)
	}

	log.Debug("Started container with ID ", b.ContainerID)

	return nil
}

func (b *Browser) killContainer() error {
	cli, err := client.NewEnvClient()
	if err != nil {
		return err
	}
	defer cli.Close()

	ctx := context.Background()

	err = b.destroyNetwork()
	if err != nil {
		return err
	}

	err = cli.ContainerKill(ctx, b.ContainerID, "")
	if err != nil {
		return err
	}

	log.Debug("Killed container with ID ", b.ContainerID)

	return nil
}

func (b *Browser) getHTML() error {
	ctx, cancel := context.WithTimeout(context.Background(),
		BrowserEventWaitTime*time.Second)
	defer cancel()
	conn, err := rpcc.DialContext(ctx, b.DebugURL)
	if err != nil {
		return err
	}
	defer conn.Close()

	cli := cdp.NewClient(conn)

	doc, err := cli.DOM.GetDocument(ctx, nil)
	if err != nil {
		return fmt.Errorf("Unable to access DOM: %s", err)
	}
	result, err := cli.DOM.GetOuterHTML(ctx, &dom.GetOuterHTMLArgs{
		NodeID: &doc.Root.NodeID,
	})
	if err != nil {
		return fmt.Errorf("Unable to retrieve HTML from DOM: %s", err)
	}
	b.HTML = result.OuterHTML
	b.HTMLSHA256, _ = hashes.StringSHA256(b.HTML)
	return nil
}

func (b *Browser) getScreenshot() error {
	ctx, cancel := context.WithTimeout(context.Background(),
		BrowserEventWaitTime*time.Second)
	defer cancel()
	conn, err := rpcc.DialContext(ctx, b.DebugURL)
	if err != nil {
		return err
	}
	defer conn.Close()

	cli := cdp.NewClient(conn)

	screenshotArgs := page.NewCaptureScreenshotArgs().
		SetFormat("png").
		SetQuality(80)
	screenshot, err := cli.Page.CaptureScreenshot(ctx, screenshotArgs)
	if err != nil {
		return fmt.Errorf("Unable to capture screenshot: %s", err)
	}
	b.ScreenshotData = base64.StdEncoding.EncodeToString(screenshot.Data)
	if b.ScreenshotPath != "" {
		if err = ioutil.WriteFile(b.ScreenshotPath, screenshot.Data, 0644); err != nil {
			log.Warning(err)
		} else {
			log.Debug("Saved screenshot at ", b.ScreenshotPath)
		}
	}
	return nil
}

func (b *Browser) aggregateRequest(event *network.RequestWillBeSentReply, isDocument bool) {
	for visitIndex, visit := range b.Visits {
		if isDocument {
			if string(event.RequestID) == visit.VisitID {
				b.Visits[visitIndex].Requests = append(b.Visits[visitIndex].Requests, event)
				return
			}
		} else {
			if string(event.LoaderID) == visit.VisitID {
				b.Visits[visitIndex].Resources = append(b.Visits[visitIndex].Resources, RequestResponse{
					Request: event,
				})
				return
			}
		}
	}

	var newVisit Visit
	if isDocument {
		newVisit = Visit{
			VisitID:  string(event.RequestID),
			Requests: []*network.RequestWillBeSentReply{event},
		}
	} else {
		newVisit = Visit{
			VisitID: string(event.LoaderID),
			Resources: []RequestResponse{
				{
					Request: event,
				},
			},
		}
	}
	b.Visits = append(b.Visits, newVisit)
}

func (b *Browser) aggregateResponse(event *network.ResponseReceivedReply, isDocument bool) {
	for visitIndex, visit := range b.Visits {
		if isDocument {
			if string(event.RequestID) == visit.VisitID {
				b.Visits[visitIndex].Response = event
				return
			}
		} else {
			if string(event.LoaderID) != visit.VisitID {
				continue
			}

			for resourceIndex, resource := range visit.Resources {
				if event.RequestID == resource.Request.RequestID {
					b.Visits[visitIndex].Resources[resourceIndex].Response = event
					return
				}
			}
		}
	}
}

func (b *Browser) aggregateVisits() {
	// First we aggregate all requests.
	for _, request := range b.RequestEvents {
		// If the RequestID is a MD5 hash, this request should be a Visit.
		if len(string(request.RequestID)) == 32 {
			b.aggregateRequest(request, true)
		} else {
			// Otherwise, it should be a resource.
			b.aggregateRequest(request, false)
		}
	}

	// Then we aggregate all responses.
	for _, response := range b.ResponseEvents {
		if len(string(response.RequestID)) == 32 {
			b.aggregateResponse(response, true)
		} else {
			b.aggregateResponse(response, false)
		}
	}

	// Then we check if any visit raised loading errors.
	for _, error := range b.ErrorEvents {
		for visitIndex, visit := range b.Visits {
			if string(error.RequestID) == visit.VisitID {
				b.Visits[visitIndex].Error = error
			}
		}
	}

	for visitIndex := range b.Visits {
		sort.Sort(ByChronologicalOrder(b.Visits[visitIndex].Requests))
	}
}

func (b *Browser) getFinalURL() error {
	ctx, cancel := context.WithTimeout(context.Background(),
		BrowserEventWaitTime*time.Second)
	defer cancel()
	conn, err := rpcc.DialContext(ctx, b.DebugURL)
	if err != nil {
		return err
	}
	defer conn.Close()

	cli := cdp.NewClient(conn)

	navHistoryReply, err := cli.Page.GetNavigationHistory(ctx)
	if err != nil {
		return fmt.Errorf("Unable to get navigation history: %s", err)
	}

	b.NavigationHistory = navHistoryReply.Entries
	b.FinalURL = navHistoryReply.Entries[len(navHistoryReply.Entries)-1].URL
	return nil
}

// Run launches our browser and navigates to the specified URL.
func (b *Browser) Run() error {
	err := b.startContainer()
	if err != nil {
		return err
	}
	defer b.killContainer()

	timeout := BrowserTimeout * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	devt := devtool.New(fmt.Sprintf("http://127.0.0.1:%d", b.DebugPort))

	log.Debug("Attempting to connect to debug port...")

	// TODO: We need to handle this better or it will fail after the count is
	//       over and the connection didn't succeed.
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

	b.DebugURL = target.WebSocketDebuggerURL
	log.Debug("Connection to debug port established at: ", b.DebugURL)

	var conn *rpcc.Conn
	if b.LogEvents {
		newLogCodec := func(conn io.ReadWriter) rpcc.Codec {
			return &LogCodec{conn: conn}
		}
		conn, err = rpcc.DialContext(ctx, b.DebugURL,
			rpcc.WithCodec(newLogCodec))
	} else {
		conn, err = rpcc.DialContext(ctx, b.DebugURL)
	}

	if err != nil {
		return err
	}
	defer conn.Close()

	cli := cdp.NewClient(conn)

	// Subscribe to events of interest.
	requestWillBeSent, err := cli.Network.RequestWillBeSent(ctx)
	if err != nil {
		return err
	}
	defer requestWillBeSent.Close()
	responseReceived, err := cli.Network.ResponseReceived(ctx)
	if err != nil {
		return err
	}
	defer responseReceived.Close()
	loadingFailed, err := cli.Network.LoadingFailed(ctx)
	if err != nil {
		return err
	}
	defer loadingFailed.Close()
	domContent, err := cli.Page.DOMContentEventFired(ctx)
	if err != nil {
		return err
	}
	defer domContent.Close()
	dialogOpening, err := cli.Page.JavascriptDialogOpening(ctx)
	if err != nil {
		return err
	}
	defer dialogOpening.Close()
	downloadWillBegin, err := cli.Page.DownloadWillBegin(ctx)
	if err != nil {
		return err
	}
	defer downloadWillBegin.Close()

	// Enable Page and Network tracking.
	if err = cli.Page.Enable(ctx); err != nil {
		return err
	}
	if err = cli.Network.Enable(ctx, nil); err != nil {
		return err
	}

	// Set the default behavior for file downloads as "deny".
	// Because we currently don't make any use of the file content
	// it's pointless to attempt to store it.
	// TODO: Review this choice.
	downloadArgs := page.NewSetDownloadBehaviorArgs("deny")
	cli.Page.SetDownloadBehavior(ctx, downloadArgs)

	// Now, navigate to the target URL.
	navArgs := page.NewNavigateArgs(b.URL).
		SetReferrer("https://mail.google.com/mail/u/0/")
	nav, err := cli.Page.Navigate(ctx, navArgs)
	if err != nil {
		return fmt.Errorf("Failed to navigate to page: %s", err)
	}

	// Navigation started!
	b.FrameID = string(nav.FrameID)
	log.Debug("Started loading on frame ID ", b.FrameID)

	stopDomContentWait := false
	stopMonitor := make(chan bool)

	go func() {
		for {
			select {
			case <-requestWillBeSent.Ready():
				event, err := requestWillBeSent.Recv()
				if err != nil {
					log.Debug("requestWillBeSent.Recv() failed: ", err)
					break
				}

				log.Debug("A request will be sent to ", event.Request.URL)

				b.RequestEvents = append(b.RequestEvents, event)
				break
			case <-responseReceived.Ready():
				event, err := responseReceived.Recv()
				if err != nil {
					log.Debug("responseReceived.Recv() failed: ", err)
					break
				}

				log.Debug("Got a response for resource of type ", event.Type.String(), " for URL ", event.Response.URL)

				// We only retrieve the content of scripts and documents.
				if (event.Type == "Script" || event.Type == "Document") && event.Response.Status == 200 {
					resp, err := cli.Network.GetResponseBody(ctx,
						&network.GetResponseBodyArgs{RequestID: event.RequestID})

					if err == nil {
						newResource := ResourceDataEntry{
							VisitID:   string(event.LoaderID),
							RequestID: string(event.RequestID),
							URL:       event.Response.URL,
							Type:      event.Type.String(),
						}
						if resp.Body != "" {
							newResource.Content = resp.Body
							newResource.SHA256, _ = hashes.StringSHA256(newResource.Content)
						}

						b.ResourcesData = append(b.ResourcesData, newResource)
					}
				}

				b.ResponseEvents = append(b.ResponseEvents, event)
				break
			case <-loadingFailed.Ready():
				event, err := loadingFailed.Recv()
				if err != nil {
					log.Debug("loadingFailed.Recv() failed: ", err)
					break
				}

				b.ErrorEvents = append(b.ErrorEvents, event)
				break
			case <-dialogOpening.Ready():
				event, err := dialogOpening.Recv()
				if err != nil {
					log.Debug("Failed to dialogOpening.Recv(): ", err)
					break
				}

				log.Debug("Browser is asked to open a dialog at URL ", event.URL,
					" of type ", event.Type.String(), " and message: ", event.Message)

				dialog := Dialog{
					URL:     event.URL,
					Type:    event.Type.String(),
					Message: event.Message,
				}

				b.Dialogs = append(b.Dialogs, dialog)

				ctx, cancel := context.WithTimeout(context.Background(),
					BrowserEventWaitTime*time.Second)
				defer cancel()
				dialogArgs := page.NewHandleJavaScriptDialogArgs(true)
				dialogArgs.SetPromptText("qwerty")
				cli.Page.HandleJavaScriptDialog(ctx, dialogArgs)
				break
			case <-downloadWillBegin.Ready():
				event, err := downloadWillBegin.Recv()
				if err != nil {
					log.Debug("Failed to downloadWillBegin.Recv(): ", err)
					break
				}

				log.Debug("Received request to download file at ", event.URL,
					" with file name ", event.SuggestedFilename)

				download := Download{
					URL:      event.URL,
					FileName: event.SuggestedFilename,
				}

				b.Downloads = append(b.Downloads, download)
				stopDomContentWait = true
				break
			case <-stopMonitor:
				return
			}
		}
	}()

	log.Debug("Before listening for DOMContentEventFired, waiting for a few seconds...")
	time.Sleep(BrowserWaitTime * time.Second)

	if stopDomContentWait {
		log.Debug("A file download was offered, no need to wait for DOMContentEventFired.")
	} else {
		_, err = domContent.Recv()
		if err != nil {
			log.Error("Waiting for DOMContentEventFired failed: ", err)
		}
	}

	log.Debug("DOMContentEventFired. Waiting for few seconds to let page finish loading...")
	time.Sleep(BrowserWaitTime * time.Second)

	stopMonitor <- true

	err = b.getHTML()
	if err != nil {
		log.Warning(err)
	}
	err = b.getScreenshot()
	if err != nil {
		log.Warning(err)
	}

	b.aggregateVisits()

	err = b.getFinalURL()
	if err != nil {
		log.Warning(err)
	}

	return nil
}
