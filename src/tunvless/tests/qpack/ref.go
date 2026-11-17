package main

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/quic-go/qpack"
)

type field struct{ name, value string }

func section(fs []field) []byte {
	var b bytes.Buffer
	e := qpack.NewEncoder(&b)
	for _, f := range fs {
		if err := e.WriteField(qpack.HeaderField{Name: f.name, Value: f.value}); err != nil {
			panic(err)
		}
	}
	e.Close()
	return b.Bytes()
}

func emit(name string, b []byte) {
	fmt.Printf("static const uint8_t %s[] = {", name)
	for i, c := range b {
		if i%12 == 0 {
			fmt.Printf("\n   ")
		}
		fmt.Printf(" 0x%02x,", c)
	}
	fmt.Printf("\n};\n")
}

func main() {
	fmt.Printf("#ifndef HY2_FROZEN_H\n#define HY2_FROZEN_H\n#include <stdint.h>\n\n")
	emit("hy2_frozen_auth", section([]field{
		{":authority", "hysteria"},
		{":method", "POST"},
		{":path", "/auth"},
		{":scheme", "https"},
		{"hysteria-auth", "pw"},
		{"hysteria-cc-rx", "0"},
		{"hysteria-padding", strings.Repeat("a", 256)},
		{"content-length", "0"},
		{"accept-encoding", "gzip"},
		{"user-agent", "quic-go HTTP/3"},
	}))
	emit("hy2_frozen_ok", section([]field{
		{":status", "233"},
		{"hysteria-udp", "true"},
		{"hysteria-cc-rx", "13107200"},
		{"hysteria-padding", strings.Repeat("b", 128)},
		{"date", "Sat, 14 Nov 2026 00:00:00 GMT"},
		{"content-length", "0"},
	}))
	emit("hy2_frozen_ok_noudp", section([]field{
		{":status", "233"},
		{"hysteria-udp", "false"},
		{"hysteria-cc-rx", "13107200"},
		{"hysteria-padding", strings.Repeat("b", 128)},
		{"date", "Sat, 14 Nov 2026 00:00:00 GMT"},
		{"content-length", "0"},
	}))
	emit("hy2_frozen_404", section([]field{
		{":status", "404"},
		{"content-type", "text/plain; charset=utf-8"},
		{"x-content-type-options", "nosniff"},
		{"content-length", "19"},
	}))
	fmt.Printf("\n#endif\n")
}
