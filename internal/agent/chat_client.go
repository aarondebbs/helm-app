package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"time"
)

// chatState is what the chat window shows: the conversation plus whether the PC is connected.
type chatState struct {
	Messages []chatLine `json:"messages"`
	Online   bool       `json:"online"`
	Enabled  bool       `json:"enabled"`
	Org      string     `json:"org"`
}

var chatHTTP = &http.Client{Timeout: 4 * time.Second}

func chatBase(s TrayStatus) (string, error) {
	if s.Control == "" || s.ChatToken == "" {
		return "", errors.New("the Helm agent is not ready yet")
	}
	return "http://" + s.Control + "/chat/" + s.ChatToken, nil
}

// chatURL is the address of the chat page served by the agent on this PC.
func chatURL(s TrayStatus) string {
	b, err := chatBase(s)
	if err != nil {
		return ""
	}
	return b + "/"
}

// chatFetch asks the local agent for the conversation. Reading it also clears the "unread" count.
func chatFetch(s TrayStatus) (chatState, error) {
	var st chatState
	b, err := chatBase(s)
	if err != nil {
		return st, err
	}
	resp, err := chatHTTP.Get(b + "/m")
	if err != nil {
		return st, errors.New("could not reach the Helm agent on this PC")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return st, errors.New("the Helm agent refused the request")
	}
	return st, json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&st)
}

// chatPost sends one message from the person at this PC.
func chatPost(s TrayStatus, text string) error {
	b, err := chatBase(s)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"text": text})
	req, _ := http.NewRequest("POST", b+"/send", bytes.NewReader(body))
	req.Header.Set("X-Helm-Chat", "1")
	req.Header.Set("Content-Type", "application/json")
	resp, err := chatHTTP.Do(req)
	if err != nil {
		return errors.New("could not reach the Helm agent on this PC")
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusTooManyRequests:
		return errors.New("you are sending messages too fast")
	case http.StatusServiceUnavailable:
		return errors.New("this PC is not connected right now")
	}
	return errors.New("the message could not be sent")
}

// readTrayStatus loads the status file the service keeps up to date.
func readTrayStatus() (TrayStatus, error) {
	var s TrayStatus
	b, err := os.ReadFile(statusPath())
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}
