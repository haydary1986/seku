package services

// Arabic text reshaper for PDF generation.
// fpdf does not support RTL or Arabic letter joining natively.
// This package provides:
// 1. Arabic letter shaping (connecting forms)
// 2. RTL text reversal for LTR PDF rendering

// arabicForm holds the 4 presentation forms for each Arabic letter.
type arabicForm struct {
	Isolated rune
	Initial  rune
	Medial   rune
	Final    rune
}

// arabicForms maps base Arabic letters to their contextual presentation forms.
var arabicForms = map[rune]arabicForm{
	// Letter: Isolated, Initial, Medial, Final
	'\u0627': {'\uFE8D', '\uFE8D', '\uFE8E', '\uFE8E'}, // Alef (non-joining right)
	'\u0628': {'\uFE8F', '\uFE91', '\uFE92', '\uFE90'}, // Ba
	'\u062A': {'\uFE95', '\uFE97', '\uFE98', '\uFE96'}, // Ta
	'\u062B': {'\uFE99', '\uFE9B', '\uFE9C', '\uFE9A'}, // Tha
	'\u062C': {'\uFE9D', '\uFE9F', '\uFEA0', '\uFE9E'}, // Jim
	'\u062D': {'\uFEA1', '\uFEA3', '\uFEA4', '\uFEA2'}, // Ha
	'\u062E': {'\uFEA5', '\uFEA7', '\uFEA8', '\uFEA6'}, // Kha
	'\u062F': {'\uFEA9', '\uFEA9', '\uFEAA', '\uFEAA'}, // Dal (non-joining right)
	'\u0630': {'\uFEAB', '\uFEAB', '\uFEAC', '\uFEAC'}, // Dhal (non-joining right)
	'\u0631': {'\uFEAD', '\uFEAD', '\uFEAE', '\uFEAE'}, // Ra (non-joining right)
	'\u0632': {'\uFEAF', '\uFEAF', '\uFEB0', '\uFEB0'}, // Zain (non-joining right)
	'\u0633': {'\uFEB1', '\uFEB3', '\uFEB4', '\uFEB2'}, // Sin
	'\u0634': {'\uFEB5', '\uFEB7', '\uFEB8', '\uFEB6'}, // Shin
	'\u0635': {'\uFEB9', '\uFEBB', '\uFEBC', '\uFEBA'}, // Sad
	'\u0636': {'\uFEBD', '\uFEBF', '\uFEC0', '\uFEBE'}, // Dad
	'\u0637': {'\uFEC1', '\uFEC3', '\uFEC4', '\uFEC2'}, // Tah
	'\u0638': {'\uFEC5', '\uFEC7', '\uFEC8', '\uFEC6'}, // Zah
	'\u0639': {'\uFEC9', '\uFECB', '\uFECC', '\uFECA'}, // Ain
	'\u063A': {'\uFECD', '\uFECF', '\uFED0', '\uFECE'}, // Ghain
	'\u0641': {'\uFED1', '\uFED3', '\uFED4', '\uFED2'}, // Fa
	'\u0642': {'\uFED5', '\uFED7', '\uFED8', '\uFED6'}, // Qaf
	'\u0643': {'\uFED9', '\uFEDB', '\uFEDC', '\uFEDA'}, // Kaf
	'\u0644': {'\uFEDD', '\uFEDF', '\uFEE0', '\uFEDE'}, // Lam
	'\u0645': {'\uFEE1', '\uFEE3', '\uFEE4', '\uFEE2'}, // Mim
	'\u0646': {'\uFEE5', '\uFEE7', '\uFEE8', '\uFEE6'}, // Nun
	'\u0647': {'\uFEE9', '\uFEEB', '\uFEEC', '\uFEEA'}, // Ha
	'\u0648': {'\uFEED', '\uFEED', '\uFEEE', '\uFEEE'}, // Waw (non-joining right)
	'\u064A': {'\uFEF1', '\uFEF3', '\uFEF4', '\uFEF2'}, // Ya
	'\u0629': {'\uFE93', '\uFE93', '\uFE94', '\uFE94'}, // Ta Marbuta (non-joining right)
	'\u0649': {'\uFEEF', '\uFEEF', '\uFEF0', '\uFEF0'}, // Alef Maksura (non-joining right)
	'\u0623': {'\uFE83', '\uFE83', '\uFE84', '\uFE84'}, // Alef Hamza Above
	'\u0625': {'\uFE87', '\uFE87', '\uFE88', '\uFE88'}, // Alef Hamza Below
	'\u0622': {'\uFE81', '\uFE81', '\uFE82', '\uFE82'}, // Alef Madda
	'\u0624': {'\uFE85', '\uFE85', '\uFE86', '\uFE86'}, // Waw Hamza
	'\u0626': {'\uFE89', '\uFE8B', '\uFE8C', '\uFE8A'}, // Ya Hamza
}

// rightJoinOnly are letters that only join to the right (not left).
var rightJoinOnly = map[rune]bool{
	'\u0627': true, // Alef
	'\u062F': true, // Dal
	'\u0630': true, // Dhal
	'\u0631': true, // Ra
	'\u0632': true, // Zain
	'\u0648': true, // Waw
	'\u0629': true, // Ta Marbuta
	'\u0649': true, // Alef Maksura
	'\u0623': true, // Alef Hamza Above
	'\u0625': true, // Alef Hamza Below
	'\u0622': true, // Alef Madda
	'\u0624': true, // Waw Hamza
}

func isArabicLetter(r rune) bool {
	return (r >= '\u0621' && r <= '\u064A') || (r >= '\uFE70' && r <= '\uFEFF')
}

func isArabicDiacritic(r rune) bool {
	return r >= '\u064B' && r <= '\u065F'
}

// ShapeArabic takes Arabic text and returns it with proper letter joining
// and reversed for LTR rendering in fpdf.
func ShapeArabic(text string) string {
	if text == "" {
		return text
	}

	runes := []rune(text)

	// First pass: identify Arabic segments and shape them
	var result []rune
	i := 0
	for i < len(runes) {
		if isArabicLetter(runes[i]) || isArabicDiacritic(runes[i]) {
			// Collect the Arabic segment
			start := i
			for i < len(runes) && (isArabicLetter(runes[i]) || isArabicDiacritic(runes[i]) || runes[i] == ' ') {
				i++
			}
			segment := runes[start:i]
			shaped := shapeArabicSegment(segment)
			// Reverse for RTL display in LTR context
			reversed := reverseRunes(shaped)
			result = append(result, reversed...)
		} else {
			result = append(result, runes[i])
			i++
		}
	}

	return string(result)
}

func shapeArabicSegment(runes []rune) []rune {
	// Filter out diacritics for shaping, we'll skip them
	var letters []rune
	for _, r := range runes {
		if !isArabicDiacritic(r) {
			letters = append(letters, r)
		}
	}

	if len(letters) == 0 {
		return runes
	}

	result := make([]rune, len(letters))
	for i, r := range letters {
		if !isArabicLetter(r) || r == ' ' {
			result[i] = r
			continue
		}

		forms, hasForm := arabicForms[r]
		if !hasForm {
			result[i] = r
			continue
		}

		prevJoins := i > 0 && isArabicLetter(letters[i-1]) && letters[i-1] != ' ' && !rightJoinOnly[letters[i-1]]
		nextJoins := i < len(letters)-1 && isArabicLetter(letters[i+1]) && letters[i+1] != ' '

		switch {
		case prevJoins && nextJoins && !rightJoinOnly[r]:
			result[i] = forms.Medial
		case prevJoins:
			result[i] = forms.Final
		case nextJoins && !rightJoinOnly[r]:
			result[i] = forms.Initial
		default:
			result[i] = forms.Isolated
		}
	}

	// Handle Lam-Alef ligatures
	result = applyLamAlef(result)

	return result
}

func applyLamAlef(runes []rune) []rune {
	var result []rune
	i := 0
	for i < len(runes) {
		if i+1 < len(runes) {
			// Check for Lam followed by Alef variants
			isLam := runes[i] == '\uFEDF' || runes[i] == '\uFEDD' || runes[i] == '\uFEE0' || runes[i] == '\uFEDE'
			if isLam {
				switch runes[i+1] {
				case '\uFE8D', '\uFE8E': // Alef
					result = append(result, '\uFEFC') // Lam-Alef ligature final
					i += 2
					continue
				case '\uFE83', '\uFE84': // Alef Hamza Above
					result = append(result, '\uFEF8') // Lam-Alef Hamza Above
					i += 2
					continue
				case '\uFE87', '\uFE88': // Alef Hamza Below
					result = append(result, '\uFEFA') // Lam-Alef Hamza Below
					i += 2
					continue
				case '\uFE81', '\uFE82': // Alef Madda
					result = append(result, '\uFEF6') // Lam-Alef Madda
					i += 2
					continue
				}
			}
		}
		result = append(result, runes[i])
		i++
	}
	return result
}

func reverseRunes(runes []rune) []rune {
	n := len(runes)
	reversed := make([]rune, n)
	for i, r := range runes {
		reversed[n-1-i] = r
	}
	return reversed
}
