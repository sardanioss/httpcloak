package engine

import "testing"

func TestOf(t *testing.T) {
	for _, tc := range []struct {
		ua   string
		want Kind
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36", Chromium},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0", Chromium},
		{"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36", Chromium},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) Gecko/20100101 Firefox/159.0", Gecko},
		{"Mozilla/5.0 (Android 15; Mobile; rv:159.0) Gecko/159.0 Firefox/159.0", Gecko},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.3 Safari/605.1.15", WebKit},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.3 Mobile/15E148 Safari/604.1", WebKit},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 26_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/155.0.7727.47 Mobile/15E148 Safari/604.1", WebKit},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 26_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/159.0 Mobile/15E148 Safari/605.1.15", WebKit},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 26_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) EdgiOS/156.0.0.0 Version/26.0 Mobile/15E148 Safari/604.1", WebKit},
		{"curl/8.11.1", Other},
		{"okhttp/4.12.0", Other},
		{"MyApp/2.1 CFNetwork/3826.400.120 Darwin/25.3.0", Other},
		{"", Other},
	} {
		if got := Of(tc.ua); got != tc.want {
			t.Errorf("Of(%q) = %v, want %v", tc.ua, got, tc.want)
		}
	}
}
