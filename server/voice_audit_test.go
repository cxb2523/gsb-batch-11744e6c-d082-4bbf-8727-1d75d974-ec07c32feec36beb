package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/mattermost/mattermost/server/public/plugin/plugintest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func auditCheckByName(t *testing.T, result voiceAuditResult, name string) voiceAuditCheck {
	t.Helper()
	for _, check := range result.Checks {
		if check.Name == name {
			return check
		}
	}
	require.FailNow(t, "audit check not found", "check %q missing from %+v", name, result.Checks)
	return voiceAuditCheck{}
}

func validAuditSnapshot() voiceAuditSnapshot {
	return voiceAuditSnapshot{
		DeclaredContentType:         "audio/webm",
		AudioBytes:                  validWebMAudioBytes(),
		RequestBodyBytes:            1024,
		MaxVoiceMessageSizeMB:       new(int64(2)),
		MaxRecordingDurationSeconds: new(int64(60)),
		ServerMaxFileSize:           new(100 * bytesPerMiB),
		DurationMS:                  "1500",
		HasMattermostUserID:         true,
		VoiceMessagesEnabled:        true,
	}
}

func TestVoiceAuditAcceptsValidUpload(t *testing.T) {
	// Given a snapshot with valid webm bytes and a valid duration.
	snapshot := validAuditSnapshot()
	// When
	result := auditVoiceMessageUpload(snapshot)
	// Then every check passes.
	require.True(t, result.Accepted, "expected all checks to pass: %+v", result.Checks)
	require.NotEmpty(t, result.Checks)
	for _, check := range result.Checks {
		assert.True(t, check.Passed, "check %q failed: %s", check.Name, check.Reason)
		assert.Empty(t, check.Reason)
		assert.Zero(t, check.HTTPStatus)
	}
	assert.Empty(t, result.DegradedFields)

	// Sniffed values match the shared detectors exactly.
	sniffedMIME, sniffedOK := detectVoiceAudioBytes(snapshot.AudioBytes)
	require.True(t, sniffedOK)
	assert.Equal(t, sniffedMIME, result.SniffedMIME)
	_, extension, extOK := detectVoiceAudio(sniffedMIME)
	require.True(t, extOK)
	assert.Equal(t, extension, result.SniffedExtension)
	assert.Equal(t, "audio/webm", result.SniffedMIME)
	assert.Equal(t, ".webm", result.SniffedExtension)
	assert.True(t, result.DeclaredSupported)
	assert.True(t, result.DeclaredMatchesSniffed)

	// Effective limits match voiceLimits for the same configuration.
	api := &plugintest.API{}
	api.On("GetConfig").Return(testServerConfig(*snapshot.ServerMaxFileSize)).Once()
	p := &Plugin{}
	p.SetAPI(api)
	limits, err := p.voiceLimits(&configuration{
		MaxVoiceMessageSizeMB:       snapshot.MaxVoiceMessageSizeMB,
		MaxRecordingDurationSeconds: snapshot.MaxRecordingDurationSeconds,
	})
	require.NoError(t, err)
	assert.Equal(t, limits.maxBytes, result.MaxBytes)
	assert.Equal(t, limits.maxDurationMS, result.MaxDurationMS)
	api.AssertExpectations(t)

	// Duration parsed and within limit.
	assert.True(t, result.DurationMSValid)
	assert.Equal(t, int64(1500), result.DurationMSValue)
	assert.True(t, result.DurationWithinLimit)
}

func TestVoiceAuditFlagsDeclaredSniffedMismatch(t *testing.T) {
	// Given a declared audio/webm type but WAV magic bytes.
	snapshot := validAuditSnapshot()
	snapshot.AudioBytes = validWAVAudioBytes()
	// When
	result := auditVoiceMessageUpload(snapshot)
	// Then the mismatch is reported with a 415.
	require.False(t, result.Accepted)
	assert.Equal(t, "audio/wav", result.SniffedMIME)
	assert.Equal(t, ".wav", result.SniffedExtension)
	assert.True(t, result.DeclaredSupported)
	assert.False(t, result.DeclaredMatchesSniffed)
	check := auditCheckByName(t, result, voiceAuditCheckDeclaredMatchesSniffed)
	assert.False(t, check.Passed)
	assert.Equal(t, http.StatusUnsupportedMediaType, check.HTTPStatus)
	assert.NotEmpty(t, check.Reason)
	// Unrelated checks still pass.
	assert.True(t, auditCheckByName(t, result, voiceAuditCheckAudioTypeDetected).Passed)
	assert.True(t, auditCheckByName(t, result, voiceAuditCheckAudioSize).Passed)
}

func TestVoiceAuditAudioSizeBoundary(t *testing.T) {
	// Given an effective limit of exactly 64 bytes (plugin size 0 inherits the server limit).
	makeAudio := func(size int) []byte {
		audio := make([]byte, size)
		copy(audio, validWebMAudioBytes())
		return audio
	}
	for _, tc := range []struct {
		name      string
		audioSize int
		accepted  bool
	}{
		{"exactly at limit", 64, true},
		{"one byte over limit", 65, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := validAuditSnapshot()
			snapshot.MaxVoiceMessageSizeMB = new(int64(0))
			snapshot.ServerMaxFileSize = new(int64(64))
			snapshot.AudioBytes = makeAudio(tc.audioSize)
			snapshot.RequestBodyBytes = int64(tc.audioSize)
			result := auditVoiceMessageUpload(snapshot)
			require.Equal(t, int64(64), result.MaxBytes)
			check := auditCheckByName(t, result, voiceAuditCheckAudioSize)
			if tc.accepted {
				assert.True(t, check.Passed, check.Reason)
				assert.True(t, result.Accepted, "expected all checks to pass: %+v", result.Checks)
			} else {
				assert.False(t, check.Passed)
				assert.Equal(t, http.StatusRequestEntityTooLarge, check.HTTPStatus)
				assert.False(t, result.Accepted)
			}
		})
	}
}

func TestVoiceAuditUnlimitedDurationAcceptsMissingDuration(t *testing.T) {
	// Given MaxRecordingDurationSeconds = 0 (duration limit disabled) and no duration_ms.
	snapshot := validAuditSnapshot()
	snapshot.MaxRecordingDurationSeconds = new(int64(0))
	snapshot.DurationMS = ""
	// When
	result := auditVoiceMessageUpload(snapshot)
	// Then the missing duration is not a rejection.
	require.Equal(t, int64(0), result.MaxDurationMS)
	assert.True(t, result.DurationMSValid)
	assert.True(t, result.DurationWithinLimit)
	assert.True(t, auditCheckByName(t, result, voiceAuditCheckDurationValid).Passed)
	assert.True(t, auditCheckByName(t, result, voiceAuditCheckDurationWithinLimit).Passed)
	assert.True(t, result.Accepted, "expected all checks to pass: %+v", result.Checks)
}

func TestVoiceAuditDurationLimitEnforcedWhenPositive(t *testing.T) {
	for _, tc := range []struct {
		name     string
		duration string
		accepted bool
	}{
		{"at limit", "2000", true},
		{"over limit", "2001", false},
		{"missing", "", false},
		{"zero", "0", false},
		{"not an integer", "abc", false},
		{"negative", "-1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := validAuditSnapshot()
			snapshot.MaxRecordingDurationSeconds = new(int64(2))
			snapshot.DurationMS = tc.duration
			result := auditVoiceMessageUpload(snapshot)
			assert.Equal(t, int64(2000), result.MaxDurationMS)
			assert.Equal(t, tc.accepted, result.Accepted, "checks: %+v", result.Checks)
			if !tc.accepted {
				assert.False(t, result.DurationWithinLimit)
			}
		})
	}
}

func TestVoiceAuditFailsClosedWhenServerLimitUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		server *int64
	}{
		{"nil server limit", nil},
		{"zero server limit", new(int64(0))},
		{"negative server limit", new(int64(-1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := validAuditSnapshot()
			snapshot.ServerMaxFileSize = tc.server
			result := auditVoiceMessageUpload(snapshot)
			require.False(t, result.Accepted)
			assert.False(t, result.LimitsAvailable)
			check := auditCheckByName(t, result, voiceAuditCheckLimitsAvailable)
			assert.False(t, check.Passed)
			assert.Equal(t, http.StatusServiceUnavailable, check.HTTPStatus)
			assert.NotEmpty(t, check.Reason)
			// Limit-dependent checks degrade instead of passing silently.
			assert.False(t, auditCheckByName(t, result, voiceAuditCheckAudioSize).Passed)
			assert.False(t, auditCheckByName(t, result, voiceAuditCheckDurationWithinLimit).Passed)
			assert.Contains(t, result.DegradedFields, "max_bytes")
			assert.Contains(t, result.DegradedFields, "max_duration_ms")
		})
	}
}

func TestVoiceAuditAuthAndSwitchChecks(t *testing.T) {
	snapshot := validAuditSnapshot()
	snapshot.HasMattermostUserID = false
	result := auditVoiceMessageUpload(snapshot)
	check := auditCheckByName(t, result, voiceAuditCheckAuthenticated)
	assert.False(t, check.Passed)
	assert.Equal(t, http.StatusUnauthorized, check.HTTPStatus)
	assert.False(t, result.Accepted)

	snapshot = validAuditSnapshot()
	snapshot.VoiceMessagesEnabled = false
	result = auditVoiceMessageUpload(snapshot)
	check = auditCheckByName(t, result, voiceAuditCheckPluginEnabled)
	assert.False(t, check.Passed)
	assert.Equal(t, http.StatusForbidden, check.HTTPStatus)
	assert.False(t, result.Accepted)
}

func TestVoiceAuditEmptyAndUnsupportedAudio(t *testing.T) {
	snapshot := validAuditSnapshot()
	snapshot.AudioBytes = nil
	result := auditVoiceMessageUpload(snapshot)
	check := auditCheckByName(t, result, voiceAuditCheckAudioPresent)
	assert.False(t, check.Passed)
	assert.Equal(t, http.StatusBadRequest, check.HTTPStatus)
	assert.False(t, result.Accepted)

	snapshot = validAuditSnapshot()
	snapshot.DeclaredContentType = "audio/aac"
	result = auditVoiceMessageUpload(snapshot)
	assert.False(t, result.DeclaredSupported)
	check = auditCheckByName(t, result, voiceAuditCheckDeclaredTypeSupported)
	assert.False(t, check.Passed)
	assert.Equal(t, http.StatusUnsupportedMediaType, check.HTTPStatus)
	assert.False(t, result.Accepted)
}

func TestVoiceAuditResultIsJSONSerializable(t *testing.T) {
	for _, snapshot := range []voiceAuditSnapshot{
		validAuditSnapshot(),
		{}, // zero-value snapshot must not panic and must still serialize
		{ServerMaxFileSize: new(int64(-5)), MaxVoiceMessageSizeMB: new(int64(-1))},
	} {
		result := auditVoiceMessageUpload(snapshot)
		encoded, err := json.Marshal(result)
		require.NoError(t, err)
		var decoded map[string]any
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		assert.Contains(t, decoded, "accepted")
		assert.Contains(t, decoded, "checks")
		assert.Contains(t, decoded, "max_bytes")
		assert.Contains(t, decoded, "max_duration_ms")
		checks, ok := decoded["checks"].([]any)
		require.True(t, ok)
		require.NotEmpty(t, checks)
		for _, raw := range checks {
			check, ok := raw.(map[string]any)
			require.True(t, ok)
			assert.Contains(t, check, "name")
			assert.Contains(t, check, "passed")
		}
	}
}
