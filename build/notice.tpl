{{ range . }}
================================================================================
{{ .Name }}  {{ .Version }}
{{ .LicenseName }}
{{ .LicenseURL }}

{{ .LicenseText }}
{{ end }}