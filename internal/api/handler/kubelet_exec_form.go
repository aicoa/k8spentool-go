package handler

import neturl "net/url"

func encodeKubeletCommandForm(command string) string {
	return neturl.Values{"cmd": []string{command}}.Encode()
}
