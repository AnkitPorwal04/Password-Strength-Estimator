// password_strength_estimator.hpp (Single file containing all logic)

#ifndef PASSWORD_STRENGTH_ESTIMATOR_HPP
#define PASSWORD_STRENGTH_ESTIMATOR_HPP

#include <string>
#include <string_view>
#include <vector>
#include <set>
#include <cmath>
#include <numeric>
#include <algorithm>
#include <map>
#include <chrono> // For performance measurement
#include <expected> // C++23
#include <ranges>   // C++20, but frequently used with C++23
#include <limits>   // For numeric_limits
#include <cstdint>  // For uint64_t
#include <iomanip>  // For std::fixed, std::setprecision in output
#include <stdexcept> // For internal logic errors, though std::expected is primary API
#include <array>     // For keyboard layouts

// For std::print if available and desired for internal debug logging,
// otherwise use traditional iostream for logging output.
// #include <print> // C++23

namespace FinTechSecurity::Password {

// --- Error Handling with std::expected ---
enum class PasswordEstimatorError {
    InvalidInput,
    InternalError,
    // Add more specific errors as needed, e_g_ FailedToLoadDictionary
};

struct ErrorInfo {
    PasswordEstimatorError code;
    std::string message;
};

// --- Data Structures for Results ---

// Represents different types of password weaknesses/vulnerabilities
enum class WeaknessType {
    None,
    TooShort,
    TooLong, // NIST suggests max length of at least 64
    CommonPassword,
    KeyboardWalk,
    SequentialPattern,
    RepeatedCharacters,
    InsufficientCharacterVariety,
    PredictablePattern, // General category for combinations of weaknesses
    // Add specific NIST-related flags, e_g_ "previously compromised" if integrated with external lookup
};

// Information about a detected weakness
struct VulnerabilityReport {
    WeaknessType type;
    std::string message;
    std::string suggestion;
};

// Estimated cracking time metrics
struct CrackTimeEstimation {
    double seconds;
    double minutes;
    double hours;
    double days;
    double months;
    double years;
    std::string human_readable; // e_g_ "3 days", "5 years"
};

// The comprehensive result structure returned by the estimator
struct PasswordStrengthResult {
    int score = 0; // 0-100, higher is stronger
    double entropy = 0.0; // Shannon entropy in bits
    CrackTimeEstimation gpu_crack_time;
    std::vector<VulnerabilityReport> vulnerabilities;
    std::string overall_feedback;
    std::chrono::microseconds performance_duration; // Time taken for estimation
};

// --- Internal Constants and Data ---

// Pre-computed common keyboard layouts for walk detection
// QWERTY layout (simplified for common walks)
// Array of arrays representing adjacent keys for simplified detection.
// A more robust solution would involve a full adjacency graph.
const std::array<std::string_view, 2> QWERTY_ROWS = {
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm"
};

const std::set<std::string_view> COMMON_PASSWORDS = {
    "password", "123456", "qwerty", "12345678", "dragon", "iloveyou",
    "abcdef", "admin", "secret", "hello", "master", "welcome", "changeme",
    // In a real system, this would be a much larger, external, efficiently-loaded dictionary.
    // For a single file, we'll keep it small for demonstration.
};

const std::set<std::string_view> DICTIONARY_WORDS = {
    // A small subset of common dictionary words.
    // In production, this would be a large, pre-hashed, or memory-mapped dictionary.
    "apple", "banana", "orange", "computer", "security", "engineer", "fintech",
    "company", "system", "authentication", "password", "strength", "estimator",
    "library", "robust", "entropy", "detect", "common", "pattern", "keyboard",
    "dictionary", "sequential", "repetition", "crack", "time", "feedback",
    "nist", "performance", "production", "error", "handling", "vulnerability",
    "report", "suggestion", "financial", "data", "processing", "code", "github",
    // Adding variations to detect "word123", "word!"
    "apple123", "security!", "pass-word", "1234password",
};

// NIST-recommended minimum length (SP 800-63B)
constexpr int MIN_PASSWORD_LENGTH = 8; // Although 15+ is better for users

// --- Helper Functions (Internal Linkage) ---

namespace detail {

/**
 * @brief Performs a constant-time comparison of two string views.
 * Essential for comparing passwords against known values to prevent timing attacks.
 * @param lhs The first string view.
 * @param rhs The second string view.
 * @return True if strings are equal, false otherwise.
 */
inline bool constant_time_equal(std::string_view lhs, std::string_view rhs) noexcept {
    if (lhs.length() != rhs.length()) {
        return false;
    }
    volatile unsigned char result = 0;
    for (size_t i = 0; i < lhs.length(); ++i) {
        result |= static_cast<unsigned char>(lhs[i] ^ rhs[i]);
    }
    return result == 0;
}

/**
 * @brief Calculates Shannon Entropy for a given password.
 * @param password The password string view.
 * @return The entropy value in bits.
 */
double calculate_shannon_entropy(std::string_view password) noexcept {
    if (password.empty()) {
        return 0.0;
    }

    std::map<char, int> char_counts;
    for (char c : password) {
        char_counts[c]++;
    }

    double entropy = 0.0;
    const double len = static_cast<double>(password.length());
    for (const auto& pair : char_counts) {
        double p = static_cast<double>(pair.second) / len;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

/**
 * @brief Detects common dictionary words in the password.
 * @param password The password string view.
 * @return std::expected containing true if a dictionary word is found, false otherwise, or an error.
 */
std::expected<bool, ErrorInfo> detect_dictionary_words(std::string_view password) noexcept {
    for (std::string_view word : DICTIONARY_WORDS) {
        // Use constant-time comparison for security
        if (detail::constant_time_equal(password, word)) {
            return true;
        }
        // Also check for sub-string presence (case-insensitive for better detection)
        // This makes it significantly slower, but more effective.
        // For sub-millisecond, this would need a more optimized data structure
        // like Aho-Corasick or pre-hashing substrings.
        // For simplicity and single-file, we do a basic contains check.
        auto lower_password = password | std::views::transform([](char c){ return static_cast<char>(std::tolower(c)); })
                                     | std::ranges::to<std::string>(); // C++23 ranges
        auto lower_word = word | std::views::transform([](char c){ return static_cast<char>(std::tolower(c)); })
                               | std::ranges::to<std::string>();

        if (lower_password.find(lower_word) != std::string::npos) {
             return true;
        }
    }
    return false;
}

/**
 * @brief Detects sequential patterns (e.g., "abc", "123", "zyxw").
 * @param password The password string view.
 * @return True if a sequential pattern is detected.
 */
bool detect_sequential_patterns(std::string_view password) noexcept {
    if (password.length() < 3) return false;

    // Check for ascending sequences (e.g., "abc", "123")
    for (size_t i = 0; i < password.length() - 2; ++i) {
        if ((password[i+1] == password[i] + 1 && password[i+2] == password[i] + 2) ||
            (password[i+1] == password[i] - 1 && password[i+2] == password[i] - 2)) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Detects character repetition (e.g., "aaa", "111").
 * @param password The password string view.
 * @return True if repetition is detected.
 */
bool detect_repetition(std::string_view password) noexcept {
    if (password.length() < 3) return false;

    // Check for "aaa", "bbb"
    for (size_t i = 0; i < password.length() - 2; ++i) {
        if (password[i] == password[i+1] && password[i+1] == password[i+2]) {
            return true;
        }
    }
    // Check for "ababab"
    if (password.length() >= 4) {
        for (size_t i = 0; i < password.length() - 3; ++i) {
            if (password[i] == password[i+2] && password[i+1] == password[i+3]) {
                return true;
            }
        }
    }
    return false;
}

/**
 * @brief Detects keyboard walk patterns (e.g., "qwerty", "asdfg").
 * This is a simplified check. A full check would map characters to keyboard coordinates.
 * @param password The password string view.
 * @return True if a keyboard walk is detected.
 */
bool detect_keyboard_walks(std::string_view password) noexcept {
    if (password.length() < 4) return false; // Typically 4+ for meaningful walks

    auto lower_password = password | std::views::transform([](char c){ return static_cast<char>(std::tolower(c)); })
                                 | std::ranges::to<std::string>();

    for (const auto& row : QWERTY_ROWS) {
        if (row.length() >= lower_password.length()) { // Check if row is long enough to contain the password
            if (row.find(lower_password) != std::string::npos) {
                return true;
            }
            // Also check reversed walks like "ytrewq"
            std::string reversed_row(row.rbegin(), row.rend());
            if (reversed_row.find(lower_password) != std::string::npos) {
                return true;
            }
        }
        // Check for diagonal patterns (more complex, simplified for this prompt)
        // e.g. "qaz", "wsx" - would need a 2D map or precomputed patterns
    }
    return false;
}

/**
 * @brief Estimates GPU-based cracking time based on entropy.
 * This is a *highly simplified* model. Real-world crack time depends on:
 * - Specific hashing algorithm (bcrypt, Argon2, scrypt, PBKDF2 are slow, MD5/SHA are fast)
 * - Salt usage and length
 * - Attacker's GPU hardware and cluster size
 * - Attacker's method (brute-force, dictionary, hybrid)
 * - Password distribution
 *
 * For a production system, this would ideally integrate with a more sophisticated
 * pre-calculated lookup table or a dedicated cracking time estimator library
 * like zxcvbn (which is JavaScript-based typically, but the logic can be ported).
 *
 * We'll use a simplified brute-force crack rate based on common GPU capabilities.
 * Assume ~100 billion guesses per second for a *fast* hash on a high-end GPU.
 * Entropy (bits) = log2(keyspace_size)
 * Keyspace_size = 2^Entropy
 * Time = Keyspace_size / guesses_per_second
 *
 * @param entropy The password entropy in bits.
 * @return Estimated crack time in seconds.
 */
double estimate_gpu_crack_time_seconds(double entropy_bits) noexcept {
    if (entropy_bits <= 0) return 0.0;

    // Approximate GPU cracking rate for a "fast" hash (e.g., unsalted MD5, SHA-1).
    // Modern GPUs can do trillions of hashes/sec for weak hashes.
    // For robust hashes (bcrypt, Argon2), it's orders of magnitude slower.
    // Let's assume a "mid-range" modern GPU for common fast hashes,
    // e.g., 100 billion guesses per second (1e11).
    // This number is purely illustrative for the purpose of the prompt.
    constexpr double GPU_GUESSES_PER_SECOND = 100'000'000'000.0; // 100 billion

    // The theoretical keyspace size
    // Using std::pow for double, but for large exponents, care is needed with precision.
    // However, entropy_bits is log2(keyspace), so 2^entropy is direct.
    double keyspace_size = std::pow(2.0, entropy_bits);

    double seconds = keyspace_size / GPU_GUESSES_PER_SECOND;

    // Cap at a very large number to prevent overflow for extremely strong passwords
    if (std::isinf(seconds) || seconds > std::numeric_limits<double>::max() / 2) {
        return std::numeric_limits<double>::max();
    }
    return seconds;
}

/**
 * @brief Converts seconds to human-readable format (e.g., "X days", "Y years").
 * @param total_seconds The total seconds.
 * @return A string with human-readable time.
 */
CrackTimeEstimation convert_seconds_to_human_readable(double total_seconds) noexcept {
    CrackTimeEstimation cte;
    cte.seconds = total_seconds;

    if (total_seconds < 60) {
        cte.human_readable = std::to_string(static_cast<int>(total_seconds)) + " seconds";
    } else if (total_seconds < 3600) {
        cte.minutes = total_seconds / 60.0;
        cte.human_readable = std::to_string(static_cast<int>(cte.minutes)) + " minutes";
    } else if (total_seconds < 86400) { // 24 * 60 * 60
        cte.hours = total_seconds / 3600.0;
        cte.human_readable = std::to_string(static_cast<int>(cte.hours)) + " hours";
    } else if (total_seconds < 31536000) { // 365 * 24 * 60 * 60
        cte.days = total_seconds / 86400.0;
        cte.human_readable = std::to_string(static_cast<int>(cte.days)) + " days";
    } else {
        cte.years = total_seconds / 31536000.0;
        // Use std::fixed and std::setprecision for better formatting of large years
        std::stringstream ss;
        ss << std::fixed << std::setprecision(2) << cte.years;
        cte.human_readable = ss.str() + " years";
    }
    return cte;
}

/**
 * @brief Helper to get character set size (e.g., 26 for lowercase, 52 for mixed case).
 * @param password The password string view.
 * @return The estimated character set size.
 */
int get_character_set_size(std::string_view password) noexcept {
    bool has_lower = false, has_upper = false, has_digit = false, has_symbol = false;
    for (char c : password) {
        if (std::islower(c)) has_lower = true;
        else if (std::isupper(c)) has_upper = true;
        else if (std::isdigit(c)) has_digit = true;
        else if (std::ispunct(c) || std::isspace(c)) has_symbol = true; // Include space as symbol per NIST
    }

    int charset_size = 0;
    if (has_lower) charset_size += 26;
    if (has_upper) charset_size += 26;
    if (has_digit) charset_size += 10;
    if (has_symbol) charset_size += 33; // Common printable ASCII symbols + space
                                         // Or a more precise count if specific symbols are allowed/disallowed.
    return charset_size;
}

} // namespace detail

// --- Main PasswordStrengthEstimator Class/Functions ---

/**
 * @brief The main function to estimate password strength.
 * This function encapsulates all logic for analysis, scoring, and reporting.
 *
 * @param password The password string to analyze.
 * @return A std::expected object containing either a PasswordStrengthResult on success,
 * or an ErrorInfo on failure.
 */
std::expected<PasswordStrengthResult, ErrorInfo> estimate_password_strength(std::string_view password) noexcept {
    auto start_time = std::chrono::high_resolution_clock::now();

    PasswordStrengthResult result;

    if (password.empty()) {
        result.vulnerabilities.push_back({WeaknessType::TooShort, "Password is empty.", "Password must not be empty. Please enter a password."});
        result.overall_feedback = "Very Weak: Empty password.";
        result.score = 0;
        auto end_time = std::chrono::high_resolution_clock::now();
        result.performance_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        return result; // Return a result even if empty, as per prompt, with score 0.
    }

    // --- 1. Basic Length Check (NIST Guidance) ---
    if (password.length() < MIN_PASSWORD_LENGTH) {
        result.vulnerabilities.push_back({WeaknessType::TooShort,
            "Password is too short. NIST recommends a minimum of 8 characters.",
            "Make your password longer. Longer passwords are significantly harder to guess."});
    }

    // NIST allows up to 64+ characters, excessively long passwords might indicate non-human input
    if (password.length() > 128) { // Arbitrary upper limit for practical purposes
        result.vulnerabilities.push_back({WeaknessType::TooLong,
            "Password is excessively long. While generally good, ensure it's not machine-generated if user-inputted.",
            "Consider a more manageable passphrase. Extremely long passwords might be unwieldy."});
    }


    // --- 2. Entropy Calculation ---
    result.entropy = detail::calculate_shannon_entropy(password);

    // --- 3. Pattern Detections ---

    // Common Password List
    for (std::string_view common_pass : COMMON_PASSWORDS) {
        if (detail::constant_time_equal(password, common_pass)) {
            result.vulnerabilities.push_back({WeaknessType::CommonPassword,
                "Password is a very common and easily guessed password.",
                "Avoid using popular or frequently breached passwords. Choose something unique."});
            break; // Found one, no need to check others
        }
    }

    // Dictionary Words (using std::expected for robust error handling)
    auto dict_check_result = detail::detect_dictionary_words(password);
    if (!dict_check_result) {
        // Handle error from dictionary check
        return std::unexpected(ErrorInfo{PasswordEstimatorError::InternalError,
                                          "Error during dictionary check: " + dict_check_result.error().message});
    }
    if (*dict_check_result) {
        result.vulnerabilities.push_back({WeaknessType::CommonPassword, // Re-use type or create new
            "Password contains or is a common dictionary word.",
            "Combine multiple unrelated words into a passphrase, or use a mix of characters and numbers."});
    }

    // Sequential Patterns
    if (detail::detect_sequential_patterns(password)) {
        result.vulnerabilities.push_back({WeaknessType::SequentialPattern,
            "Password contains easily predictable sequential characters (e.g., 'abc', '123').",
            "Avoid consecutive letters or numbers. Mix up character order."});
    }

    // Repetition
    if (detail::detect_repetition(password)) {
        result.vulnerabilities.push_back({WeaknessType::RepeatedCharacters,
            "Password contains repeating character sequences (e.g., 'aaa', 'abab').",
            "Vary your character choices. Avoid simple repetitions."});
    }

    // Keyboard Walks
    if (detail::detect_keyboard_walks(password)) {
        result.vulnerabilities.push_back({WeaknessType::KeyboardWalk,
            "Password resembles a common keyboard pattern (e.g., 'qwerty', 'asdfgh').",
            "Do not use patterns found on a keyboard. These are very easy to guess."});
    }

    // Character Variety Check
    bool has_upper = false, has_lower = false, has_digit = false, has_symbol = false;
    for (char c : password) {
        if (std::islower(c)) has_lower = true;
        else if (std::isupper(c)) has_upper = true;
        else if (std::isdigit(c)) has_digit = true;
        else if (std::ispunct(c) || std::isspace(c)) has_symbol = true;
    }
    int char_types_count = (has_upper ? 1 : 0) + (has_lower ? 1 : 0) + (has_digit ? 1 : 0) + (has_symbol ? 1 : 0);
    if (char_types_count < 3 && password.length() < 12) { // Less variety + shorter length = weaker
        result.vulnerabilities.push_back({WeaknessType::InsufficientCharacterVariety,
            "Password lacks variety in character types (e.g., only lowercase letters).",
            "Include a mix of uppercase and lowercase letters, numbers, and symbols to increase complexity."});
    }


    // --- 4. GPU-based Crack Time Estimation ---
    result.gpu_crack_time = detail::convert_seconds_to_human_readable(
        detail::estimate_gpu_crack_time_seconds(result.entropy)
    );

    // --- 5. Scoring and Overall Feedback (NIST-aligned) ---
    // Scoring is heuristic and combines factors.
    // NIST generally prefers length and entropy over forced complexity.

    int base_score = static_cast<int>(result.entropy * 4); // Basic score based on entropy, max ~400 for 100 bits

    // Adjust score based on length (NIST emphasis)
    if (password.length() >= 15) { // NIST suggests 15+ as a good target
        base_score += 20;
    } else if (password.length() >= 12) {
        base_score += 10;
    }

    // Penalize for detected weaknesses
    for (const auto& vuln : result.vulnerabilities) {
        switch (vuln.type) {
            case WeaknessType::TooShort:              base_score -= 30; break;
            case WeaknessType::CommonPassword:        base_score -= 50; break; // Most severe
            case WeaknessType::KeyboardWalk:          base_score -= 40; break;
            case WeaknessType::SequentialPattern:     base_score -= 30; break;
            case WeaknessType::RepeatedCharacters:    base_score -= 20; break;
            case WeaknessType::InsufficientCharacterVariety: base_score -= 15; break;
            case WeaknessType::TooLong:               /* Minor penalty or ignore */ break;
            default: break;
        }
    }

    // Ensure score is within 0-100 range
    result.score = std::max(0, std::min(100, base_score));

    // Generate overall feedback
    if (result.score >= 90) {
        result.overall_feedback = "Excellent! Your password is very strong and highly resistant to common attacks.";
    } else if (result.score >= 75) {
        result.overall_feedback = "Strong: Your password is good, but consider adding more variety or length for maximum security.";
    } else if (result.score >= 50) {
        result.overall_feedback = "Moderate: Your password offers some protection, but has identifiable weaknesses. Review suggestions.";
    } else if (result.score >= 25) {
        result.overall_feedback = "Weak: Your password has significant vulnerabilities. It's recommended to change it immediately.";
    } else {
        result.overall_feedback = "Very Weak: Your password offers almost no protection. Please create a new, strong password.";
    }

    // Add crack time to overall feedback
    result.overall_feedback += " Estimated GPU crack time: " + result.gpu_crack_time.human_readable + ".";

    // Performance tracking
    auto end_time = std::chrono::high_resolution_clock::now();
    result.performance_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);

    // If performance is an issue, add a warning
    if (result.performance_duration.count() > 1000) { // Sub-millisecond = < 1000 microseconds
        result.vulnerabilities.push_back({WeaknessType::InternalError, // Using InternalError for reporting
            "Performance Warning: Password estimation exceeded sub-millisecond target (" +
            std::to_string(result.performance_duration.count()) + " us).",
            "This could indicate an extremely long password or inefficient pattern matching. Optimize internal lookups if this occurs frequently."});
    }

    return result;
}

} // namespace FinTechSecurity::Password

#endif // PASSWORD_STRENGTH_ESTIMATOR_HPP

// --- Main function for demonstration/testing (optional, typically in a separate .cpp) ---
// For a single file, it would be included here with #ifdef or similar,
// or as a simple example in comments. Let's put a basic example.

#include <iostream>

int main() {
    using namespace FinTechSecurity::Password;

    std::vector<std::string> test_passwords = {
        "",                     // Empty
        "short",                // Too short
        "password",             // Common
        "123456",               // Common sequential digits
        "qwerty",               // Keyboard walk
        "asdfghjkl",            // Longer keyboard walk
        "aaaaaaa",              // Repetition
        "abcde123",             // Sequential mixed
        "Pa$$w0rd!",            // Basic mixed
        "MySup3rS3cur3P@ssphr@se2025!", // Strong
        "thisisalongpassphraseforsecurity", // Long, somewhat random
        "passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpassword", // Extremely long
        "tr0ub4dor&3",          // From NIST example
        "correct horse battery staple", // Passphrase
        "12345passwordABC!@#",  // Mixed weak patterns
        "Password123!@#" // Good but guessable
    };

    std::cout << "--- Password Strength Estimator (C++23) ---\n\n";

    for (const auto& p : test_passwords) {
        std::cout << "Analyzing password: \"" << p << "\"\n";
        auto result_expected = estimate_password_strength(p);

        if (result_expected) {
            const auto& result = *result_expected;
            std::cout << "  Score: " << result.score << "/100\n";
            std::cout << "  Entropy: " << std::fixed << std::setprecision(2) << result.entropy << " bits\n";
            std::cout << "  Crack Time (GPU): " << result.gpu_crack_time.human_readable << "\n";
            std::cout << "  Performance: " << result.performance_duration.count() << " microseconds\n";
            std::cout << "  Overall Feedback: " << result.overall_feedback << "\n";

            if (!result.vulnerabilities.empty()) {
                std::cout << "  Vulnerabilities and Suggestions:\n";
                for (const auto& vuln : result.vulnerabilities) {
                    std::cout << "    - " << vuln.message << "\n";
                    std::cout << "      Suggestion: " << vuln.suggestion << "\n";
                }
            } else {
                std::cout << "  No specific vulnerabilities detected.\n";
            }
        } else {
            const auto& error = result_expected.error();
            std::cerr << "  ERROR: " << error.message << " (Code: " << static_cast<int>(error.code) << ")\n";
        }
        std::cout << "\n----------------------------------------\n\n";
    }

    return 0;
}
