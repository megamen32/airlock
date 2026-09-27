package trigger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
)

// UserbotDriver keeps Telegram credentials and polling in one local GramJS
// relay. Airlock owns identity admission, conversations, tools and scheduling.
type UserbotDriver struct {
	baseURL       string
	client        *http.Client
	storageOrigin string
}

func NewUserbotDriver() *UserbotDriver {
	return &UserbotDriver{baseURL: "http://127.0.0.1:30192", client: &http.Client{Timeout: 45 * time.Second}, storageOrigin: os.Getenv("S3_URL_PUBLIC")}
}
func (d *UserbotDriver) Init(context.Context, *dbq.Bridge) error { return nil }
func (d *UserbotDriver) Activate(ctx context.Context, br dbq.Bridge) error {
	return d.request(ctx, br, "GET", "/health", nil, nil)
}
func (d *UserbotDriver) Teardown(context.Context, dbq.Bridge) error                      { return nil }
func (d *UserbotDriver) DefaultEcho() bool                                               { return false }
func (d *UserbotDriver) RemoveButtons(context.Context, dbq.Bridge, string, string) error { return nil }

func (d *UserbotDriver) request(ctx context.Context, br dbq.Bridge, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, d.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+br.BotTokenRef)
	req.Header.Set("Content-Type", "application/json")
	res, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("local Telegram relay unavailable: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("local Telegram relay HTTP %d (delivery was not retried)", res.StatusCode)
	}
	if output != nil {
		return json.NewDecoder(io.LimitReader(res.Body, 32<<20)).Decode(output)
	}
	return nil
}

type userbotConfig struct {
	After int64 `json:"after"`
}
type userbotFile struct {
	Filename    string `json:"filename"`
	ContentType string `json:"contentType"`
	Data        []byte `json:"dataBase64"`
	IsVoiceNote bool   `json:"isVoiceNote"`
	FileRef     string `json:"fileRef"`
}
type userbotEvent struct {
	Seq         int64         `json:"seq"`
	MessageID   string        `json:"messageId"`
	ChatID      string        `json:"chatId"`
	SenderID    string        `json:"senderId"`
	SenderName  string        `json:"senderName"`
	Text        string        `json:"text"`
	Direct      bool          `json:"isDirectMessage"`
	ShouldReply *bool         `json:"shouldReply,omitempty"`
	Files       []userbotFile `json:"files"`
}

func (d *UserbotDriver) Poll(ctx context.Context, br *dbq.Bridge) ([]BridgeEvent, error) {
	var cfg userbotConfig
	if len(br.Config) > 0 && string(br.Config) != "{}" {
		if err := json.Unmarshal(br.Config, &cfg); err != nil {
			return nil, err
		}
	}
	var response struct {
		Events     []userbotEvent `json:"events"`
		NextCursor int64          `json:"nextCursor"`
	}
	if err := d.request(ctx, *br, "GET", "/events?after="+strconv.FormatInt(cfg.After, 10), nil, &response); err != nil {
		return nil, err
	}
	events := make([]BridgeEvent, 0, len(response.Events))
	last := cfg.After
	for _, ev := range response.Events {
		if ev.Seq <= last || ev.MessageID == "" || ev.ChatID == "" || ev.SenderID == "" || (ev.Direct && ev.SenderID != ev.ChatID) {
			return nil, fmt.Errorf("invalid authenticated relay event")
		}
		last = ev.Seq
		e := BridgeEvent{BridgeID: uuid.UUID(br.ID.Bytes), ExternalID: ev.ChatID, SenderID: ev.SenderID, SenderName: ev.SenderName, Text: ev.Text}
		for _, f := range ev.Files {
			if f.FileRef != "" {
				if len(f.FileRef) != 64 {
					return nil, fmt.Errorf("invalid relay file reference")
				}
				if _, err := hex.DecodeString(f.FileRef); err != nil {
					return nil, fmt.Errorf("invalid relay file reference")
				}
				req, err := http.NewRequestWithContext(ctx, "GET", d.baseURL+"/files/"+f.FileRef, nil)
				if err != nil {
					return nil, err
				}
				req.Header.Set("Authorization", "Bearer "+br.BotTokenRef)
				res, err := d.client.Do(req)
				if err != nil {
					return nil, err
				}
				data, readErr := io.ReadAll(io.LimitReader(res.Body, (24<<20)+1))
				res.Body.Close()
				if readErr != nil || res.StatusCode != http.StatusOK || len(data) > 24<<20 {
					return nil, fmt.Errorf("relay attachment unavailable or too large")
				}
				f.Data = data
			}
			e.Files = append(e.Files, BridgeFile{Filename: f.Filename, ContentType: f.ContentType, Data: f.Data, Size: int64(len(f.Data)), IsVoiceNote: f.IsVoiceNote})
		}
		fields := strings.Fields(ev.Text)
		if len(fields) == 2 && (fields[0] == "/approve" || fields[0] == "/deny" || fields[0] == "/cancel") {
			if _, err := uuid.Parse(fields[1]); err == nil {
				e.Callback = &BridgeCallback{Data: strings.TrimPrefix(fields[0], "/") + ":" + fields[1]}
				e.Text = ""
			}
		}
		e.RawPayload, _ = json.Marshal(ev)
		events = append(events, e)
	}
	if response.NextCursor != last {
		return nil, fmt.Errorf("relay cursor does not match received events")
	}
	cfg.After = last
	br.Config, _ = json.Marshal(cfg)
	if len(events) == 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return events, nil
}

type relayIncomingKey struct{}

func relayDeliveryKey(ctx context.Context, scope, body string) string {
	incoming, _ := ctx.Value(relayIncomingKey{}).(string)
	if incoming == "" {
		incoming = uuid.NewString()
	}
	sum := sha256.Sum256([]byte(incoming + "\n" + scope))
	return hex.EncodeToString(sum[:])
}
func (d *UserbotDriver) sendText(ctx context.Context, br dbq.Bridge, chat, text, key string) error {
	return d.request(ctx, br, "POST", "/send", map[string]string{"chatId": chat, "text": text, "idempotencyKey": key}, nil)
}
func (d *UserbotDriver) SendStream(ctx context.Context, br dbq.Bridge, chat string, echo bool, events <-chan ResponseEvent) (string, error) {
	var text strings.Builder
	var rendered strings.Builder
	var firstErr error
	index := 0
	flush := func() {
		if text.Len() == 0 {
			return
		}
		value := text.String()
		text.Reset()
		key := relayDeliveryKey(ctx, chat+":"+strconv.Itoa(index), value)
		index++
		if err := d.sendText(ctx, br, chat, value, key); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return
		}
		rendered.WriteString(value)
	}
	for ev := range events {
		switch ev.Type {
		case "text-delta":
			text.WriteString(ev.Text)
		case "confirmation_required":
			flush()
			description := ev.Description
			if description == "" {
				description = "Подтверди действие: " + ev.Permission
			}
			text.WriteString(description + "\n" + ev.Code + "\nПодтвердить: /approve " + ev.RunID + "\nОтклонить: /deny " + ev.RunID)
			flush()
		case "info":
			if ev.Text != "" {
				flush()
				text.WriteString(ev.Text)
				flush()
			}
		case "error":
			flush()
			text.WriteString("Не удалось завершить запрос. Попробуй ещё раз позже.")
			flush()
		}
	}
	flush()
	return rendered.String(), firstErr
}
func (d *UserbotDriver) SendParts(ctx context.Context, br dbq.Bridge, chat string, parts []wire.DisplayPart) error {
	for i, p := range parts {
		key := relayDeliveryKey(ctx, chat+":"+strconv.Itoa(i), p.Type+p.Text+p.Filename+string(p.Data))
		if p.Type == "text" {
			if p.Text != "" {
				if err := d.sendText(ctx, br, chat, p.Text, key); err != nil {
					return err
				}
			}
			continue
		}
		if p.Type == "file" || p.Type == "image" || p.Type == "audio" || p.Type == "video" {
			if len(p.Data) == 0 {
				origin, err := url.Parse(d.storageOrigin)
				if err != nil || origin.Host == "" {
					return fmt.Errorf("userbot file storage origin is not configured")
				}
				u, err := url.Parse(p.URL)
				if err != nil || u.Scheme != origin.Scheme || u.Host != origin.Host || u.User != nil {
					return fmt.Errorf("userbot file requires platform storage URL")
				}
				client := *d.client
				client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
					return fmt.Errorf("storage redirects are not allowed")
				}
				req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
				if err != nil {
					return err
				}
				res, err := client.Do(req)
				if err != nil {
					return fmt.Errorf("fetch exported file failed")
				}
				data, readErr := io.ReadAll(io.LimitReader(res.Body, (24<<20)+1))
				res.Body.Close()
				if readErr != nil || res.StatusCode != http.StatusOK || len(data) > 24<<20 {
					return fmt.Errorf("exported file unavailable or too large")
				}
				p.Data = data
			}
			if err := d.request(ctx, br, "POST", "/file", map[string]any{"chatId": chat, "idempotencyKey": key, "filename": p.Filename, "dataBase64": p.Data, "caption": p.Text}, nil); err != nil {
				return err
			}
		}
	}
	return nil
}
