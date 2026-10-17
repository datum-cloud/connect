package commands

import (
	"io"
	"strings"

	"rsc.io/qr"
)

// quietZone is the light border the QR spec requires around the code, in modules.
const quietZone = 4

// writeQR draws text as a QR code using half-block characters, two modules
// per character row. Colors are explicit (black on bright white) so the code
// is never inverted by a dark or light terminal theme, which many scanners
// cannot read.
func writeQR(w io.Writer, text string) error {
	code, err := qr.Encode(text, qr.L)
	if err != nil {
		return err
	}
	size := code.Size + 2*quietZone
	dark := func(x, y int) bool {
		x, y = x-quietZone, y-quietZone
		return x >= 0 && y >= 0 && x < code.Size && y < code.Size && code.Black(x, y)
	}
	var b strings.Builder
	for y := 0; y < size; y += 2 {
		for x := 0; x < size; x++ {
			// "▀" paints the top module in the foreground color and the
			// bottom module in the background color.
			b.WriteString(fgColor(dark(x, y)))
			b.WriteString(bgColor(y+1 < size && dark(x, y+1)))
			b.WriteString("▀")
		}
		b.WriteString("\033[0m\n")
	}
	_, err = io.WriteString(w, b.String())
	return err
}

func fgColor(dark bool) string {
	if dark {
		return "\033[30m"
	}
	return "\033[97m"
}

func bgColor(dark bool) string {
	if dark {
		return "\033[40m"
	}
	return "\033[107m"
}
