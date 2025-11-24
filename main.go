package main

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

//go:embed data.json
var dataFile embed.FS

// fetchContent is a helper to fetch content from a URL with custom headers
func fetchContent(targetURL string, headers map[string]string) ([]byte, http.Header, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("upstream returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	return body, resp.Header, err
}

// ProxyMasterHandler handles the /master.m3u8 endpoint
func ProxyMasterHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
    id := q.Get("id")
    cookieB64 := q.Get("cookie")
    if id == "" || cookieB64 == "" {
        http.Error(w, "missing id or cookie", http.StatusBadRequest)
        return
    }

    cookieJSON, err := base64.StdEncoding.DecodeString(cookieB64)
    if err != nil {
        http.Error(w, "invalid cookie encoding", http.StatusBadRequest)
        return
    }
    var cm map[string]string
    if err := json.Unmarshal(cookieJSON, &cm); err != nil {
        http.Error(w, "invalid cookie payload", http.StatusBadRequest)
        return
    }

    cookieStr := cm["cookie"]   
    d, err := readDataFile()
    if err != nil {
        http.Error(w, "failed to read data.json", http.StatusInternalServerError)
        return
    }
	var target string
    for _, item := range d.Data {
        if item.ID == id {
            target = item.URL
            break
        }
    }
    if target == "" {
        http.Error(w, "id not found", http.StatusNotFound)
        return
    }

    // append cookie string as query string
    finalURL := target + "?" + cookieStr
	
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	prefix := fmt.Sprintf("%s://%s", scheme, r.Host)

	handlePlaylist(w, r, true, finalURL, prefix)
}

// ProxyIndexHandler handles the /index.m3u8 endpoint
func ProxyIndexHandler(w http.ResponseWriter, r *http.Request) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	prefix := fmt.Sprintf("%s://%s", scheme, r.Host)
	handlePlaylist(w, r, false, "", prefix)
}

// transformURL helper to generate proxy URLs
func transformURL(relURLStr string, baseURL *url.URL, headersStr string, isMaster bool, prefix string) string {
	relURL, err := url.Parse(relURLStr)
	if err != nil {
		return relURLStr
	}

	absURL := baseURL.ResolveReference(relURL).String()

	path := relURL.Path
	if path == "" {
		path = relURL.String()
	}

	// Simple extension check
	isM3U8 := strings.Contains(path, ".m3u8")
	isSegment := strings.Contains(path, ".ts") || strings.Contains(path, ".mp4")
	segmentType := ""
	if strings.Contains(path, ".mp4") {
		segmentType = "mp4"
	} else {
		segmentType = "ts"
	}
	if isM3U8 {
		// Extract query params from original relative URL for 'data'
		//origQuery := relURL.RawQuery
		// encodedData := ""
		// if origQuery != "" {
		// 	encodedData = base64.StdEncoding.EncodeToString([]byte(origQuery))
		// }

		// Construct new URL
		newParams := url.Values{}
		newParams.Set("url", absURL)
		newParams.Set("headers", headersStr)
		// if encodedData != "" {
		// 	newParams.Set("data", encodedData)
		// }

		return fmt.Sprintf("%s/index.m3u8?%s", prefix, newParams.Encode())

	} else if isSegment && !isMaster {
		// Proxy segments only in Index handler
		newParams := url.Values{}
		newParams.Set("url", absURL)
		newParams.Set("headers", headersStr)
		// No data param for segments as per instructions point 18

		return fmt.Sprintf("%s/segment.%s?%s", prefix, segmentType, newParams.Encode())
	}

	// Fallback: use absolute URL
	return absURL
}

// handlePlaylist contains the common logic for processing m3u8 playlists
func handlePlaylist(w http.ResponseWriter, r *http.Request, isMaster bool, targetURLStr string, prefix string) {
	// 1. Get query params
	if !isMaster {
		targetURLStr = r.URL.Query().Get("url")
	}
	headersStr := r.URL.Query().Get("headers")
	//dataStr := r.URL.Query().Get("data")

	if targetURLStr == "" {
		http.Error(w, "missing url param", http.StatusBadRequest)
		return
	}

	// Parse headers
	headers := make(map[string]string)
	if headersStr != "" {
		if err := json.Unmarshal([]byte(headersStr), &headers); err != nil {
			log.Printf("Error parsing headers: %v\n", err)
		}
	}

	// Append data if present (specifically for Index handler as per instructions)
	// Point 14: "decode and append the query params passed as 'data'"
	// if !isMaster && dataStr != "" {
	// 	decodedBytes, err := base64.StdEncoding.DecodeString(dataStr)
	// 	if err == nil {
	// 		decodedQuery := string(decodedBytes)
	// 		if decodedQuery != "" {
	// 			if strings.Contains(targetURLStr, "?") {
	// 				targetURLStr += "&" + decodedQuery
	// 			} else {
	// 				targetURLStr += "?" + decodedQuery
	// 			}
	// 		}
	// 	}
	// }

	// Fetch content
	content, _, err := fetchContent(targetURLStr, headers)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to fetch: %v", err), http.StatusInternalServerError)
		return
	}

	// Base URL for resolution
	baseURL, err := url.Parse(targetURLStr)
	if err != nil {
		http.Error(w, "invalid target url", http.StatusBadRequest)
		return
	}

	// Process content
	var processedLines []string
	scanner := bufio.NewScanner(bytes.NewReader(content))
	
	// Regex for EXT-X-MEDIA URI
	reMediaURI := regexp.MustCompile(`URI="([^"]+)"`)

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" {
			processedLines = append(processedLines, line)
			continue
		}
		if strings.HasPrefix(trimmed, "#EXT-X-MAP") {
			// Handle URI inside EXT-X-MAP
			matches := reMediaURI.FindStringSubmatch(trimmed)
			if len(matches) > 1 {
				originalURI := matches[1]
				newURI := transformURL(originalURI, baseURL, headersStr, isMaster, prefix)
				line = strings.Replace(line, originalURI, newURI, 1)
			}
			processedLines = append(processedLines, line)
			continue
		}
		if strings.HasPrefix(trimmed, "#EXT-X-MEDIA") {
			// Handle URI inside EXT-X-MEDIA
			matches := reMediaURI.FindStringSubmatch(trimmed)
			if len(matches) > 1 {
				originalURI := matches[1]
				newURI := transformURL(originalURI, baseURL, headersStr, isMaster, prefix)
				line = strings.Replace(line, originalURI, newURI, 1)
			}
			processedLines = append(processedLines, line)
			continue
		}

		if strings.HasPrefix(trimmed, "#") {
			processedLines = append(processedLines, line)
			continue
		}

		// It's a URI line
		newLine := transformURL(trimmed, baseURL, headersStr, isMaster, prefix)
		processedLines = append(processedLines, newLine)
	}

	w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
	w.Header().Set("Access-Control-Allow-Origin", "*") // Good practice for proxy

	for _, l := range processedLines {
		fmt.Fprintln(w, l)
	}
}

// ProxySegmentHandler handles the /segment.ts endpoint
func ProxySegmentHandler(w http.ResponseWriter, r *http.Request) {
	targetURLStr := r.URL.Query().Get("url")
	headersStr := r.URL.Query().Get("headers")
	//dataStr := r.URL.Query().Get("data")

	if targetURLStr == "" {
		http.Error(w, "missing url param", http.StatusBadRequest)
		return
	}

	headers := make(map[string]string)
	if headersStr != "" {
		json.Unmarshal([]byte(headersStr), &headers)
	}

	// Point 20: "decode and append the query params passed as 'data'"
	// if dataStr != "" {
	// 	decodedBytes, err := base64.StdEncoding.DecodeString(dataStr)
	// 	if err == nil {
	// 		decodedQuery := string(decodedBytes)
	// 		if decodedQuery != "" {
	// 			if strings.Contains(targetURLStr, "?") {
	// 				targetURLStr += "&" + decodedQuery
	// 			} else {
	// 				targetURLStr += "?" + decodedQuery
	// 			}
	// 		}
	// 	}
	// }

	content, respHeaders, err := fetchContent(targetURLStr, headers)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to fetch: %v", err), http.StatusInternalServerError)
		return
	}

	// Copy headers
	if ct := respHeaders.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if cl := respHeaders.Get("Content-Length"); cl != "" {
		w.Header().Set("Content-Length", cl)
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")

	w.Write(content)
}

type ChannelItem struct {
    ID   string `json:"id"`
    Name string `json:"name"`
    URL  string `json:"url"`
    Logo string `json:"logo"`
}

type DataFile struct {
    Title string        `json:"title"`
    Data  []ChannelItem `json:"data"`
}

func readDataFile() (*DataFile, error) {
    b, err := dataFile.ReadFile("data.json")
    if err != nil {
        return nil, err
    }
    var d DataFile
    if err := json.Unmarshal(b, &d); err != nil {
        return nil, err
    }
    return &d, nil
}

// playlistHandler responds with an M3U playlist referencing /index.m3u8 for each channel
func ProxyPlaylistHandler(cache *expirable.LRU[string, string]) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        d, err := readDataFile()
        if err != nil {
            http.Error(w, "failed to read data.json", http.StatusInternalServerError)
            return
        }

        ua := r.Header.Get("User-Agent")
        if ua == "" {
            // pick a random UA from the list
            ua = userAgents[rand.IntN(len(userAgents))]
        }

        uaHash := getMD5Hash(ua)
        cachedCookie, found := cache.Get(uaHash)
        
        cookieB64 := ""
        if found {
            cookieB64 = cachedCookie
        } else {
            cookieMap, err := generateCookieZee5(ua)
            if err != nil {
                http.Error(w, fmt.Sprintf("failed to generate cookie: %v", err), http.StatusInternalServerError)
                return
            }

            cookieJSON, err := json.Marshal(cookieMap)
            if err != nil {
                http.Error(w, "failed to encode cookie", http.StatusInternalServerError)
                return
            }
            cookieB64 = base64.StdEncoding.EncodeToString(cookieJSON)
            cache.Add(uaHash, cookieB64)
        }
        
        w.Header().Set("Content-Type", "audio/x-mpegurl")
        fmt.Fprintln(w, "#EXTM3U")
        scheme := "http"
        if r.TLS != nil {
            scheme = "https"
        }
        prefix := fmt.Sprintf("%s://%s", scheme, r.Host)
        for _, item := range d.Data {
            if item.ID == "" || item.URL == "" {
                continue
            }
            fmt.Fprintf(w, "#EXTINF:-1 tvg-id=\"%s\" tvg-name=\"%s\" tvg-logo=\"%s\", %s\n", item.ID, item.Name, item.Logo, item.Name)
            headers := make(map[string]string)
            headers["User-Agent"] = ua
            headersBytes, err := json.Marshal(headers)
            if err != nil {
                http.Error(w, "failed to encode headers", http.StatusInternalServerError)
                return
            }
            vals := url.Values{}
            vals.Set("id", item.ID)
            vals.Set("headers", string(headersBytes)) 
            vals.Set("cookie", cookieB64)
            fmt.Fprintf(w, "%s/master.m3u8?%s\n", prefix, vals.Encode())
        }
    }
}

func ProxyRootHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/plain; charset=utf-8")
    fmt.Fprintln(w, "zee5-go: dummy root")
}

func main() {
	cache := expirable.NewLRU[string, string](50, nil, time.Second*3600)
	http.HandleFunc("/", ProxyRootHandler)
    http.HandleFunc("/playlist.m3u", ProxyPlaylistHandler(cache))
	http.HandleFunc("/master.m3u8", ProxyMasterHandler)
	http.HandleFunc("/index.m3u8", ProxyIndexHandler)
	http.HandleFunc("/segment.ts", ProxySegmentHandler)
	http.HandleFunc("/segment.mp4", ProxySegmentHandler)

	port := "8080"
	log.Printf("Proxy server starting on port %s...", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
