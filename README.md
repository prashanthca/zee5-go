# ZEE5 IPTV

## Prerequisites

- [Go](https://go.dev/dl/) (version 1.16 or later recommended)

## Installation & Build

1.  Clone the repository (or download the source code).
2.  Navigate to the project directory.
3.  Build the application:

    ```bash
    go build -o zee5-proxy.exe .
    ```

## Usage

1.  Run the built executable:

    ```bash
    ./zee5-proxy.exe
    ```

    The server will start on port `8080`.

2.  **Get the Playlist**:
    Open your IPTV player (like VLC, TiviMate, OTT Navigator) and use the following URL for the playlist:

    ```
    http://localhost:8080/playlist.m3u
    ```

    This playlist contains all the channels defined in `data.json`.

## Endpoints

-   `/playlist.m3u`: Returns the master M3U playlist with all channels.
-   `/master.m3u8`: Proxies the master playlist for a specific channel.
-   `/index.m3u8`: Proxies child playlists (quality levels).
-   `/segment.ts` / `/segment.mp4`: Proxies the actual video/audio segments.

## Credits

- https://github.com/yuvraj824/zee5

## Disclaimer

This project is for **educational purposes only**. It is intended to demonstrate how HTTP proxying and M3U8 playlist manipulation work in Go. 
