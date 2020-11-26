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
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
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

type Response struct {
	RequestID  string      `json:"request_id"`
	Failed     bool        `json:"failed"`
	Error      string      `json:"error"`
	Status     int         `json:"status"`
	IPAddress  string      `json:"ip_address"`
	PortNumber int         `json:"port_number"`
	URL        string      `json:"url"`
	Type       string      `json:"type"`
	Headers    interface{} `json:"headers"`
	Mime       string      `json:"mime"`
	SHA256     string      `json:"sha256"`
	Content    string      `json:"content"`
}

type Request struct {
	Timestamp int64    `json:"timestamp"`
	Method    string   `json:"method"`
	URL       string   `json:"url"`
	Type      string   `json:"type"`
	Initiator string   `json:"initiator"`
	RequestID string   `json:"request_id"`
	FrameID   string   `json:"frame_id"`
	Response  Response `json:"response"`
}

type ByChronologicalOrder []Request

func (a ByChronologicalOrder) Len() int {
	return len(a)
}
func (a ByChronologicalOrder) Less(i, j int) bool {
	return a[i].Timestamp < a[j].Timestamp
}
func (a ByChronologicalOrder) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

// Download contains details of files which were offered for download at the link.
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

// Browser is a struct containing details over a browser navigation to a URL.
type Browser struct {
	URL            string     `json:"url"`
	FinalURL       string     `json:"final_url"`
	Requests       []Request  `json:"requests"`
	Responses      []Response `json:"responses"`
	Downloads      []Download `json:"downloads"`
	Dialogs        []Dialog   `json:"dialogs"`
	HTML           string     `json:"html"`
	ScreenshotPath string     `json:"screenshot_path"`
	ScreenshotData string     `json:"screenshot_data"`
	UseTor         bool       `json:"use_tor"`
	DebugPort      int        `json:"debug_port"`
	DebugURL       string     `json:"debug_url"`
	LogEvents      bool       `json:"log_events"`
	UserAgent      string     `json:"user_agent"`
	ImageName      string     `json:"image_name"`
	ContainerID    string     `json:"container_id"`
	FrameID        string     `json:"frame_id"`
}

// Adapted from: https://pkg.go.dev/github.com/mafredri/cdp#example-package-Logging
// LogCodec captures the output from writing RPC requests and reading
// responses on the connection. It implements rpcc.Codec via
// WriteRequest and ReadResponse.
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

// NewBrowser instantiates a new Browser struct.
func NewBrowser(url string, screenshotPath string, useTor bool, logEvents bool, imageName string) *Browser {
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

	log.Debug("Using debug port: ", b.DebugPort)
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

	resp, err := cli.ContainerCreate(ctx, config, hostConfig, nil, "")
	if err != nil {
		return fmt.Errorf("Unable to create container: %s", err)
	}

	b.ContainerID = resp.ID

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

				newRequest := Request{
					Timestamp: event.Timestamp.Time().UnixNano(),
					Method:    event.Request.Method,
					URL:       event.DocumentURL,
					Type:      event.Type.String(),
					Initiator: event.Initiator.Type,
					RequestID: string(event.RequestID),
					FrameID:   string(*event.FrameID),
				}
				b.Requests = append(b.Requests, newRequest)
				break
			case <-responseReceived.Ready():
				event, err := responseReceived.Recv()
				if err != nil {
					log.Debug("responseReceived.Recv() failed: ", err)
					break
				}

				var resourceURL string
				if strings.HasPrefix(event.Response.URL, "data:") {
					resourceURL = "<data object>"
				} else {
					resourceURL = event.Response.URL
				}

				log.Debug("Received response with status ", event.Response.Status,
					" for resource of type ", event.Type.String(), " at URL: ", resourceURL)

				newResponse := Response{
					RequestID:  string(event.RequestID),
					Failed:     false,
					Status:     event.Response.Status,
					IPAddress:  *event.Response.RemoteIPAddress,
					PortNumber: *event.Response.RemotePort,
					URL:        resourceURL,
					Type:       event.Type.String(),
					Headers:    event.Response.Headers,
					Mime:       event.Response.MimeType,
				}

				// We only retrieve the content of scripts and documents.
				if (event.Type == "Script" || event.Type == "Document") && event.Response.Status == 200 {
					resp, err := cli.Network.GetResponseBody(ctx,
						&network.GetResponseBodyArgs{RequestID: event.RequestID})

					if err == nil {
						newResponse.Content = fmt.Sprintf("%s", resp.Body)
						if newResponse.Content != "" {
							newResponse.SHA256 = GetSHA256Hash(newResponse.Content)
						}
					}
				}

				b.Responses = append(b.Responses, newResponse)
				break
			case <-loadingFailed.Ready():
				event, err := loadingFailed.Recv()
				if err != nil {
					log.Debug("loadingFailed.Recv() failed: ", err)
					break
				}

				newResponse := Response{
					RequestID: string(event.RequestID),
					Failed:    true,
					Error:     event.ErrorText,
					Type:      event.Type.String(),
				}
				b.Responses = append(b.Responses, newResponse)
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

	// Assign FinalURL.
	if len(b.Requests) > 0 {
		sort.Sort(ByChronologicalOrder(b.Requests))

		// We just loop through all requests, find those of type Document
		// and which loaded at the original frame.
		// TODO: This currently means that pages loaded through JavaScript
		//       redirects such as window.location are not considered visits.
		//       Need to review this choice.
		for _, request := range b.Requests {
			if request.FrameID != b.FrameID {
				continue
			}

			if request.Type == "Document" && request.Initiator == "other" {
				b.FinalURL = request.URL
			}
		}
	}

	// We assign responses to the relative requests.
	// NOTE: We only do this now because of potential race condtions that
	//       could occur trying to do this while processing events earlier.
	for _, response := range b.Responses {
		for index, request := range b.Requests {
			if request.RequestID != response.RequestID {
				continue
			}

			b.Requests[index].Response = response
		}
	}

	return nil
}
