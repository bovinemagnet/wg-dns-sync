package wireguard

import (
	"fmt"
	"strings"
)

type PeerMatchError struct{ Message string }

func (e PeerMatchError) Error() string { return e.Message }

func UpdatePeerAllowedIPs(content, targetPublicKey string, allowedIPs []string) (string, error) {
	lines := strings.Split(content, "\n")
	peerRanges := peerSections(lines)
	if len(peerRanges) == 0 {
		return "", PeerMatchError{Message: "no [Peer] sections found"}
	}

	targets := make([]sectionRange, 0, 1)
	for _, sec := range peerRanges {
		pub, _ := findKey(lines, sec, "PublicKey")
		if pub == targetPublicKey {
			targets = append(targets, sec)
		}
	}
	if len(targets) == 0 {
		return "", PeerMatchError{Message: "target peer public key not found"}
	}
	if len(targets) > 1 {
		return "", PeerMatchError{Message: "multiple peers match target public key"}
	}
	target := targets[0]
	allowedLine := fmt.Sprintf("AllowedIPs = %s", strings.Join(allowedIPs, ", "))

	idxs := keyIndexes(lines, target, "AllowedIPs")
	if len(idxs) > 0 {
		lines[idxs[0]] = allowedLine
		for i := len(idxs) - 1; i >= 1; i-- {
			lines = append(lines[:idxs[i]], lines[idxs[i]+1:]...)
		}
	} else {
		insertAt := target.end
		lines = append(lines[:insertAt], append([]string{allowedLine}, lines[insertAt:]...)...)
	}

	out := strings.Join(lines, "\n")
	if strings.HasSuffix(content, "\n") && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return out, nil
}

func ValidateTargetPeer(content, targetPublicKey string) error {
	_, err := UpdatePeerAllowedIPs(content, targetPublicKey, []string{"0.0.0.0/32"})
	return err
}

type sectionRange struct {
	start int
	end   int
}

func peerSections(lines []string) []sectionRange {
	sections := []sectionRange{}
	current := sectionRange{start: -1, end: len(lines)}
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			if current.start >= 0 {
				current.end = i
				sections = append(sections, current)
			}
			if strings.EqualFold(t, "[Peer]") {
				current = sectionRange{start: i, end: len(lines)}
			} else {
				current = sectionRange{start: -1, end: len(lines)}
			}
		}
	}
	if current.start >= 0 {
		sections = append(sections, current)
	}
	return sections
}

func parseKV(line string) (string, string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
		return "", "", false
	}
	idx := strings.Index(trimmed, "=")
	if idx < 0 {
		return "", "", false
	}
	key := strings.TrimSpace(trimmed[:idx])
	val := strings.TrimSpace(trimmed[idx+1:])
	return key, val, true
}

func findKey(lines []string, sec sectionRange, key string) (string, bool) {
	for i := sec.start + 1; i < sec.end; i++ {
		k, v, ok := parseKV(lines[i])
		if ok && strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

func keyIndexes(lines []string, sec sectionRange, key string) []int {
	var out []int
	for i := sec.start + 1; i < sec.end; i++ {
		k, _, ok := parseKV(lines[i])
		if ok && strings.EqualFold(k, key) {
			out = append(out, i)
		}
	}
	return out
}
