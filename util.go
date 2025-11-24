package main

import (
    "bytes"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "regexp"
    "strings"
    "crypto/md5"
    "encoding/hex"
    "github.com/google/uuid"
)

var userAgents = []string{
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.94 AOL/9.7 AOLBuild/4343.4049.US Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) CriOS/45.0.2454.68 Mobile/12H143 Safari/600.1.4",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:38.0) Gecko/20100101 Firefox/38.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:37.0) Gecko/20100101 Firefox/37.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:39.0) Gecko/20100101 Firefox/39.0",
}

func getMD5Hash(text string) string {
   hash := md5.Sum([]byte(text))
   return hex.EncodeToString(hash[:])
}

// generateDDToken generates the 'x-dd-token' header value by Base64 encoding
// a JSON string of device capabilities.
func generateDDToken() (string, error) {
    data := map[string]interface{}{
        "schema_version": "1",
        "os_name": "N/A",
        "os_version": "N/A",
        "platform_name": "Chrome",
        "platform_version": "104",
        "device_name": "",
        "app_name": "Web",
        "app_version": "2.52.31",
        "player_capabilities": map[string]interface{}{
            "audio_channel": []string{"STEREO"},
            "video_codec":   []string{"H264"},
            "container":     []string{"MP4", "TS"},
            "package":       []string{"DASH", "HLS"},
            "resolution":    []string{"240p", "SD", "HD", "FHD"},
            "dynamic_range": []string{"SDR"},
        },
        "security_capabilities": map[string]interface{}{
            "encryption":              []string{"WIDEVINE_AES_CTR"},
            "widevine_security_level": []string{"L3"},
            "hdcp_version":            []string{"HDCP_V1", "HDCP_V2", "HDCP_V2_1", "HDCP_V2_2"},
        },
    }

    jsonBytes, err := json.Marshal(data)
    if err != nil {
        return "", fmt.Errorf("failed to marshal JSON: %w", err)
    }

    // Base64 encode the JSON bytes
    encoded := base64.StdEncoding.EncodeToString(jsonBytes)

    return encoded, nil
}

// generateGuestToken generates a version 4 (random) UUID string.
func generateGuestToken() string {
    return uuid.New().String()
}

// fetchPlatformToken fetches the Zee5 page and extracts the 'gwapiPlatformToken'
// using a regular expression.
func fetchPlatformToken(userAgent string) (string, error) {
    urlStr := "https://www.zee5.com/live-tv/aaj-tak/0-9-aajtak"

    client := &http.Client{}
    req, err := http.NewRequest("GET", urlStr, nil)
    if err != nil {
        return "", fmt.Errorf("failed to create request: %w", err)
    }
    req.Header.Set("User-Agent", userAgent)

    resp, err := client.Do(req)
    if err != nil {
        return "", fmt.Errorf("error fetching page: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("unexpected status code %d", resp.StatusCode)
    }

    bodyBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", fmt.Errorf("failed to read response body: %w", err)
    }

    re := regexp.MustCompile(`"gwapiPlatformToken"\s*:\s*"([^"]+)"`)
    matches := re.FindStringSubmatch(string(bodyBytes))
    if len(matches) > 1 {
        return matches[1], nil
    }
    return "", fmt.Errorf("platform token not found in page")
}

// fetchM3u8URL orchestrates the token generation and performs the final API call
// to retrieve the M3U8 video stream URL.
func fetchM3u8URL(guestToken, platformToken, ddToken string, userAgent string) (string, error) {
    // API configuration
    baseURL := "https://spapi.zee5.com/singlePlayback/getDetails/secure"
    
    // Construct the full URL with query parameters
    u, err := url.Parse(baseURL)
    if err != nil {
        return "", fmt.Errorf("failed to parse base URL: %w", err)
    }
    
    q := u.Query()
    q.Set("channel_id", "0-9-9z583538")
    q.Set("device_id", guestToken)
    q.Set("platform_name", "desktop_web")
    q.Set("translation", "en")
    q.Set("user_language", "en,hi,te")
    q.Set("country", "IN")
    q.Set("state", "")
    q.Set("app_version", "4.24.0")
    q.Set("user_type", "guest")
    q.Set("check_parental_control", "false")
    u.RawQuery = q.Encode()
    fullURL := u.String()
    
    // Payload for the POST request
    payload := map[string]string{
        "x-access-token": platformToken,
        "X-Z5-Guest-Token": guestToken,
        "x-dd-token": ddToken,
    }

    jsonPayload, err := json.Marshal(payload)
    if err != nil {
        return "", fmt.Errorf("failed to marshal payload: %w", err)
    }

    client := &http.Client{}
    req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(jsonPayload))
    if err != nil {
        return "", fmt.Errorf("failed to create request: %w", err)
    }

    req.Header.Set("accept", "application/json")
    req.Header.Set("content-type", "application/json")
    req.Header.Set("origin", "https://www.zee5.com")
    req.Header.Set("referer", "https://www.zee5.com/")
    req.Header.Set("user-agent", userAgent)

    resp, err := client.Do(req)
    if err != nil {
        return "", fmt.Errorf("request failed: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("invalid response from API, status %d", resp.StatusCode)
    }

    var responseData map[string]interface{}
    if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
        return "", fmt.Errorf("json decode error: %w", err)
    }

    // Extract the 'video_token'
    keyOsDetails, ok := responseData["keyOsDetails"].(map[string]interface{})
    if !ok {
        fmt.Fprintln(os.Stderr, "Error: Could not fetch m3u8 URL (keyOsDetails missing).")
        os.Exit(1)
    }

    videoToken, ok := keyOsDetails["video_token"].(string)
    if !ok || videoToken == "" {
        fmt.Fprintln(os.Stderr, "Error: Could not fetch m3u8 URL (video_token missing).")
        os.Exit(1)
    }
    
    // Simple URL validation check
    if strings.HasPrefix(videoToken, "http") {
        return videoToken, nil
    }
    return "", fmt.Errorf("invalid video_token url")
}

// generateCookieZee5 fetches the M3U8 URL content and extracts the 'hdntl'
// token/cookie from the response body using a regular expression.
func generateCookieZee5(userAgent string) (map[string]string, error) {
    // 1. Get required tokens
    guestToken := generateGuestToken()
    
    platformToken, err := fetchPlatformToken(userAgent)
    if err != nil {
        return nil, err
    }

    ddToken, err := generateDDToken()
    if err != nil {
        return nil, err
    }

    // 2. Fetch the M3U8 URL
    m3u8URL, err := fetchM3u8URL(guestToken, platformToken, ddToken, userAgent)
    if err != nil {
        return nil, err
    }

    // 3. Fetch the M3U8 content to get the 'hdntl' cookie
    client := &http.Client{
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return nil
        },
    }
    req, err := http.NewRequest("GET", m3u8URL, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to create M3U8 content request: %w", err)
    }
    req.Header.Set("User-Agent", userAgent)

    resp, err := client.Do(req)
    if err != nil {
        return nil, fmt.Errorf("error fetching M3U8 content: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("error fetching M3U8 content, status code: %d", resp.StatusCode)
    }

    bodyBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read M3U8 content body: %w", err)
    }
    body := string(bodyBytes)

    re := regexp.MustCompile(`hdntl=([^\s"]+)`)
    matches := re.FindStringSubmatch(body)
    if len(matches) > 0 {
        return map[string]string{"cookie": matches[0]}, nil
    }
    return nil, fmt.Errorf("hdntl token not found in response")
}