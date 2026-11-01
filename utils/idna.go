package utils

import (
	"net"
	"net/url"

	"golang.org/x/net/idna"
)

// ConvertIDNToASCII 将包含国际化域名(IDN)的 URL 转换为 ASCII 兼容编码(ACE)格式
// 例如: "https://中文域名.com" -> "https://xn--fiq228c.com"
func ConvertIDNToASCII(urlStr string) (string, error) {
	// 解析 URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return urlStr, err
	}

	hostname := parsedURL.Hostname()

	// 检查是否为 IP 地址(IPv4 或 IPv6),如果是则不需要转换
	if net.ParseIP(hostname) != nil {
		return parsedURL.String(), nil
	}

	// 转换主机名为 Punycode
	asciiHost, err := idna.ToASCII(hostname)
	if err != nil {
		return urlStr, err
	}

	// 如果有端口,需要保留
	if parsedURL.Port() != "" {
		parsedURL.Host = asciiHost + ":" + parsedURL.Port()
	} else {
		parsedURL.Host = asciiHost
	}

	return parsedURL.String(), nil
}
