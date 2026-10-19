package bridge

type Page struct {
	Body  []byte
	Nonce string
	CSP   string
}

const PermissionsPolicy = "accelerometer=(), autoplay=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-create=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), web-share=(), xr-spatial-tracking=()"

// Render generates a bridge Page using the default factory for the specified parameters.
func Render(hostname, basePath, bootstrapToken, carrierMode string, batchBytes int) (Page, error) {
	return DefaultFactory().Render(Options{
		Hostname:       hostname,
		BasePath:       basePath,
		BootstrapToken: bootstrapToken,
		CarrierMode:    carrierMode,
		BatchBytes:     batchBytes,
	})
}

// RenderWithOptions generates a bridge Page using the default factory with extended options (e.g. Platform, Template).
func RenderWithOptions(opts Options) (Page, error) {
	return DefaultFactory().Render(opts)
}
