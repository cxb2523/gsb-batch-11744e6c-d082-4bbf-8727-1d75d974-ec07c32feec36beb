package main

import (
	"net/http"
	"sort"
	"strconv"
)

// Check names emitted by auditVoiceMessageUpload, in evaluation order.
const (
	voiceAuditCheckAuthenticated          = "authenticated"
	voiceAuditCheckPluginEnabled          = "plugin_enabled"
	voiceAuditCheckLimitsAvailable        = "limits_available"
	voiceAuditCheckAudioPresent           = "audio_present"
	voiceAuditCheckAudioSize              = "audio_size_within_limit"
	voiceAuditCheckRequestBodySize        = "request_body_within_limit"
	voiceAuditCheckDeclaredTypeSupported  = "declared_type_supported"
	voiceAuditCheckAudioTypeDetected      = "audio_type_detected"
	voiceAuditCheckDeclaredMatchesSniffed = "declared_matches_sniffed"
	voiceAuditCheckDurationValid          = "duration_ms_valid"
	voiceAuditCheckDurationWithinLimit    = "duration_ms_within_limit"
)

// voiceAuditSnapshot is a pure-data description of a voice message upload
// preflight. It carries no request handles, API clients, or other references.
type voiceAuditSnapshot struct {
	DeclaredContentType         string `json:"declared_content_type"`
	AudioBytes                  []byte `json:"audio_bytes,omitempty"`
	RequestBodyBytes            int64  `json:"request_body_bytes"`
	MaxVoiceMessageSizeMB       *int64 `json:"max_voice_message_size_mb,omitempty"`
	MaxRecordingDurationSeconds *int64 `json:"max_recording_duration_seconds,omitempty"`
	ServerMaxFileSize           *int64 `json:"server_max_file_size,omitempty"`
	DurationMS                  string `json:"duration_ms"`
	HasMattermostUserID         bool   `json:"has_mattermost_user_id"`
	VoiceMessagesEnabled        bool   `json:"voice_messages_enabled"`
}

// voiceAuditCheck is one ordered preflight check. HTTPStatus is the status the
// upload handler would return when the check fails; it is 0 when Passed.
type voiceAuditCheck struct {
	Name       string `json:"name"`
	Passed     bool   `json:"passed"`
	Reason     string `json:"reason,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

// voiceAuditResult is the structured, JSON-serializable outcome of an upload
// preflight audit. It contains only plain data: no errors, no functions.
type voiceAuditResult struct {
	Accepted               bool              `json:"accepted"`
	SniffedMIME            string            `json:"sniffed_mime,omitempty"`
	SniffedExtension       string            `json:"sniffed_extension,omitempty"`
	DeclaredSupported      bool              `json:"declared_supported"`
	DeclaredMatchesSniffed bool              `json:"declared_matches_sniffed"`
	LimitsAvailable        bool              `json:"limits_available"`
	MaxBytes               int64             `json:"max_bytes"`
	MaxDurationMS          int64             `json:"max_duration_ms"`
	DurationMSValue        int64             `json:"duration_ms_value"`
	DurationMSValid        bool              `json:"duration_ms_valid"`
	DurationWithinLimit    bool              `json:"duration_within_limit"`
	DegradedFields         []string          `json:"degraded_fields,omitempty"`
	Checks                 []voiceAuditCheck `json:"checks"`
}

// pureVoiceLimits mirrors (*Plugin).voiceLimits without touching the
// Mattermost API: the server file size limit arrives as plain data instead.
// A non-empty reason means the limits are unavailable (the handler's 503 path).
func pureVoiceLimits(sizeMB *int64, durationSeconds *int64, serverMaxFileSize *int64) (maxBytes int64, maxDurationMS int64, reason string) {
	size := defaultMaxVoiceMessageSizeMB
	if sizeMB != nil {
		size = *sizeMB
	}
	if size < 0 || size > maxSafeJSONInteger/bytesPerMiB {
		return 0, 0, "invalid MaxVoiceMessageSizeMB"
	}
	duration := defaultMaxRecordingDurationSeconds
	if durationSeconds != nil {
		duration = *durationSeconds
	}
	if duration < 0 || duration > maxSafeJSONInteger/1000 {
		return 0, 0, "invalid MaxRecordingDurationSeconds"
	}
	if serverMaxFileSize == nil {
		return 0, 0, "mattermost file size limit is unavailable"
	}
	serverMaxBytes := *serverMaxFileSize
	if serverMaxBytes <= 0 || serverMaxBytes > maxSafeJSONInteger {
		return 0, 0, "invalid Mattermost file size limit"
	}
	maxBytes = size * bytesPerMiB
	if maxBytes == 0 || maxBytes > serverMaxBytes {
		maxBytes = serverMaxBytes
	}
	return maxBytes, duration * 1000, ""
}

// auditVoiceMessageUpload evaluates the same preflight rules as
// handleCreateVoiceMessage against a pure-data snapshot. It never reads a
// request body, never calls the Mattermost API, and never touches disk.
// Missing inputs or unusable server limits yield a degraded result that
// fails closed and names the affected fields, never a panic.
func auditVoiceMessageUpload(snapshot voiceAuditSnapshot) voiceAuditResult {
	result := voiceAuditResult{Checks: []voiceAuditCheck{}}
	degraded := map[string]bool{}

	addCheck := func(name string, passed bool, reason string, status int) {
		if passed {
			reason = ""
			status = 0
		}
		result.Checks = append(result.Checks, voiceAuditCheck{Name: name, Passed: passed, Reason: reason, HTTPStatus: status})
	}
	degradeCheck := func(name string, field string, reason string) {
		addCheck(name, false, reason, http.StatusServiceUnavailable)
		degraded[field] = true
	}

	// 1. Authentication (handler: 401).
	addCheck(voiceAuditCheckAuthenticated, snapshot.HasMattermostUserID, "Not authorized", http.StatusUnauthorized)

	// 2. Plugin switch (handler: 403).
	addCheck(voiceAuditCheckPluginEnabled, snapshot.VoiceMessagesEnabled, "Voice messages are disabled", http.StatusForbidden)

	// 3. Effective limits (handler: 503 when unavailable).
	maxBytes, maxDurationMS, limitsReason := pureVoiceLimits(snapshot.MaxVoiceMessageSizeMB, snapshot.MaxRecordingDurationSeconds, snapshot.ServerMaxFileSize)
	result.LimitsAvailable = limitsReason == ""
	if result.LimitsAvailable {
		result.MaxBytes = maxBytes
		result.MaxDurationMS = maxDurationMS
		addCheck(voiceAuditCheckLimitsAvailable, true, "", 0)
	} else {
		addCheck(voiceAuditCheckLimitsAvailable, false, "Voice message limits are unavailable: "+limitsReason, http.StatusServiceUnavailable)
		degraded["max_bytes"] = true
		degraded["max_duration_ms"] = true
	}

	// 4. Audio part must be non-empty (handler: 400).
	addCheck(voiceAuditCheckAudioPresent, len(snapshot.AudioBytes) > 0, "Empty audio file", http.StatusBadRequest)

	// 5. Audio size against the effective limit (handler: 413).
	switch {
	case !result.LimitsAvailable:
		degradeCheck(voiceAuditCheckAudioSize, "audio_size_within_limit", "Cannot evaluate audio size: voice message limits are unavailable")
	case int64(len(snapshot.AudioBytes)) > maxBytes:
		addCheck(voiceAuditCheckAudioSize, false, "Voice message too large", http.StatusRequestEntityTooLarge)
	default:
		addCheck(voiceAuditCheckAudioSize, true, "", 0)
	}

	// 6. Whole request body against maxBytes+multipartOverheadBytes (handler: 413).
	// A non-positive RequestBodyBytes means the total is unknown and is not audited.
	switch {
	case !result.LimitsAvailable:
		degradeCheck(voiceAuditCheckRequestBodySize, "request_body_within_limit", "Cannot evaluate request body size: voice message limits are unavailable")
	case snapshot.RequestBodyBytes > maxBytes+multipartOverheadBytes:
		addCheck(voiceAuditCheckRequestBodySize, false, "Voice message too large", http.StatusRequestEntityTooLarge)
	default:
		addCheck(voiceAuditCheckRequestBodySize, true, "", 0)
	}

	// 7. Declared Content-Type, when present, must be supported (handler: 415).
	declaredMIME := ""
	declaredOK := true
	if snapshot.DeclaredContentType != "" {
		var ok bool
		declaredMIME, _, ok = detectVoiceAudio(snapshot.DeclaredContentType)
		declaredOK = ok
	}
	result.DeclaredSupported = declaredOK
	addCheck(voiceAuditCheckDeclaredTypeSupported, declaredOK, "Unsupported audio type", http.StatusUnsupportedMediaType)

	// 8. Sniff the audio bytes (handler: 415 when unrecognized).
	sniffedMIME, sniffedOK := detectVoiceAudioBytes(snapshot.AudioBytes)
	if sniffedOK {
		result.SniffedMIME = sniffedMIME
		_, extension, extOK := detectVoiceAudio(sniffedMIME)
		if extOK {
			result.SniffedExtension = extension
		}
	}
	addCheck(voiceAuditCheckAudioTypeDetected, sniffedOK, "Unsupported audio type", http.StatusUnsupportedMediaType)

	// 9. Declared and sniffed types must match (handler: 415). An absent
	// declared type imposes no constraint, matching parseVoiceAudioPart.
	matches := true
	if declaredMIME != "" {
		matches = sniffedOK && voiceAudioMimeTypesMatch(declaredMIME, sniffedMIME)
	}
	result.DeclaredMatchesSniffed = matches
	addCheck(voiceAuditCheckDeclaredMatchesSniffed, matches, "Declared content type does not match detected audio type", http.StatusUnsupportedMediaType)

	// 10. duration_ms must parse as a non-negative safe integer (handler: 400).
	durationValue := int64(0)
	durationValid := true
	if snapshot.DurationMS != "" {
		parsed, err := strconv.ParseInt(snapshot.DurationMS, 10, 64)
		if err != nil || parsed < 0 || parsed > maxSafeJSONInteger {
			durationValid = false
		} else {
			durationValue = parsed
		}
	}
	result.DurationMSValue = durationValue
	result.DurationMSValid = durationValid
	addCheck(voiceAuditCheckDurationValid, durationValid, "Invalid duration_ms", http.StatusBadRequest)

	// 11. Duration limit (handler: 400, only enforced when maxDurationMS > 0).
	switch {
	case !durationValid:
		addCheck(voiceAuditCheckDurationWithinLimit, false, "Cannot evaluate duration limit: duration_ms is invalid", http.StatusBadRequest)
	case !result.LimitsAvailable:
		degradeCheck(voiceAuditCheckDurationWithinLimit, "duration_within_limit", "Cannot evaluate duration limit: voice message limits are unavailable")
	case maxDurationMS > 0 && (durationValue <= 0 || durationValue > maxDurationMS):
		addCheck(voiceAuditCheckDurationWithinLimit, false, "duration_ms must be positive and within the recording duration limit", http.StatusBadRequest)
	default:
		addCheck(voiceAuditCheckDurationWithinLimit, true, "", 0)
		result.DurationWithinLimit = true
	}

	result.Accepted = true
	for _, check := range result.Checks {
		if !check.Passed {
			result.Accepted = false
			break
		}
	}
	for field := range degraded {
		result.DegradedFields = append(result.DegradedFields, field)
	}
	sort.Strings(result.DegradedFields)

	return result
}
