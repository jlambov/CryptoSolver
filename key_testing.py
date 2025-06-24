"""
Advanced Key Testing System for Kryptos Cipher Analysis
Implements comprehensive key testing strategies including dictionary attacks,
brute force, cipher variants, and known plaintext validation.
"""

import itertools
import string
from typing import List, Dict, Tuple, Optional, Generator
from collections import Counter
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing

class KeyTester:
    """Comprehensive key testing system for cipher analysis"""
    
    def __init__(self):
        self.known_plaintext_k4 = [
            ("EASTNORTHEAST", 22, 34, "NORTHEAST"),  # Including typo variant
            ("BERLIN", 64, 69, "BERLIN"),
            ("CLOCK", 70, 74, "CLOCK")
        ]
        
        # Priority keys for testing (including user-specified keys)
        self.priority_keys = [
            "HOWS", "UNDERGRUUND", "DESPARATLY", "IQLUSION",
            "KRYPTOS", "CIA", "LANGLEY", "SCULPTURE", "CRYPTOGRAPHY", "CIPHER"
        ]
        
        # Common dictionary words for key testing
        self.common_words = [
            "KRYPTOS", "CIA", "LANGLEY", "SCULPTURE", "CRYPTOGRAPHY", "CIPHER",
            "SECRET", "CODE", "PUZZLE", "MYSTERY", "SANBORN", "SCHEIDT",
            "INTELLIGENCE", "AGENCY", "VIRGINIA", "HEADQUARTERS", "PALIMPSEST",
            "BETWEEN", "SUBTLE", "SHADES", "REALITY", "SLOWLY", "DESPAIRING",
            "MOMENTS", "OPENING", "SHADOWS", "VIRTUALLY", "INVISIBLE",
            "EAST", "NORTH", "NORTHEAST", "BERLIN", "CLOCK", "LAYER",
            "TWO", "FOUR", "SEVEN", "NINE", "YARD", "MAIN", "BUILDING",
            "HOWS", "UNDERGRUUND", "DESPARATLY", "IQLUSION", "UNDERGROUND",
            "DESPERATELY", "ILLUSION", "QUESTION", "ANSWER", "TRUTH", "FALSE"
        ]
        
        # Extended dictionary for comprehensive testing
        self.extended_words = self._load_extended_dictionary()
        
    def _load_extended_dictionary(self) -> List[str]:
        """Load extended dictionary for key testing"""
        # Common English words and cryptography-related terms
        extended = [
            "ALPHABET", "ANALYSIS", "ATTACK", "BREAK", "CRYPTANALYSIS",
            "DECIPHER", "DECODE", "DECRYPT", "ENCRYPT", "FREQUENCY",
            "HIDDEN", "KEY", "MESSAGE", "PATTERN", "PLAINTEXT", "SUBSTITUTION",
            "TRANSPOSITION", "VIGENERE", "AUTOKEY", "RUNNING", "TABLE",
            "MATRIX", "GRID", "COLUMNAR", "REVERSE", "BACKWARD", "FORWARD",
            "SCULPTURE", "ARTIST", "COPPER", "METAL", "CURVED", "TEXT",
            "VIRGINIA", "WASHINGTON", "AMERICA", "UNITED", "STATES",
            "GOVERNMENT", "FEDERAL", "NATIONAL", "SECURITY", "DEFENSE"
        ]
        return self.common_words + extended

    def generate_key_candidates(self, max_length: int = 15, include_phrases: bool = True, 
                               custom_keys: List[str] = None) -> Generator[str, None, None]:
        """Generate key candidates for testing"""
        
        # 0. Priority keys first (including custom keys)
        all_priority_keys = self.priority_keys.copy()
        if custom_keys:
            all_priority_keys.extend(custom_keys)
        
        for key in all_priority_keys:
            if len(key) <= max_length:
                yield key
        
        # 1. Single words from dictionary
        for word in self.extended_words:
            if len(word) <= max_length and word not in all_priority_keys:
                yield word
        
        # 2. Multi-key combinations (user-specified keys combined)
        if custom_keys and len(custom_keys) > 1:
            for key1 in custom_keys:
                for key2 in custom_keys:
                    if key1 != key2:
                        combined = key1 + key2
                        if len(combined) <= max_length:
                            yield combined
        
        # 3. Multi-word phrases
        if include_phrases:
            for word1 in self.common_words[:20]:  # Limit for performance
                for word2 in self.common_words[:20]:
                    phrase = word1 + word2
                    if len(phrase) <= max_length and phrase not in all_priority_keys:
                        yield phrase
        
        # 4. Modified versions of priority keys
        for word in all_priority_keys:
            if len(word) <= max_length:
                # Reversed
                reversed_word = word[::-1]
                if reversed_word != word:
                    yield reversed_word
                # With numbers
                for i in range(10):
                    if len(word + str(i)) <= max_length:
                        yield word + str(i)
                # Partial keys (useful for longer words)
                if len(word) > 8:
                    for start in range(0, len(word) - 3):
                        for end in range(start + 4, min(len(word) + 1, start + max_length + 1)):
                            partial = word[start:end]
                            if len(partial) >= 4:
                                yield partial
        
        # 5. Brute force short keys (computationally intensive)
        if max_length <= 6:
            for length in range(3, max_length + 1):
                for key in itertools.product(string.ascii_uppercase, repeat=length):
                    yield ''.join(key)

    def test_vigenere_variants(self, ciphertext: str, key: str) -> Dict[str, Tuple[str, float]]:
        """Test different Vigenère cipher variants with given key"""
        results = {}
        
        # 1. Standard Vigenère
        from ciphers import VigenereCipher
        vigenere = VigenereCipher()
        
        try:
            decrypted = vigenere.decrypt(ciphertext, key)
            score = self._score_decryption(decrypted, ciphertext)
            results['standard'] = (decrypted, score)
        except:
            results['standard'] = ("", 0.0)
        
        # 2. Auto-key Vigenère
        try:
            decrypted = self._autokey_decrypt(ciphertext, key)
            score = self._score_decryption(decrypted, ciphertext)
            results['autokey'] = (decrypted, score)
        except:
            results['autokey'] = ("", 0.0)
        
        # 3. With text reversal (pre-processing)
        try:
            reversed_cipher = ciphertext[::-1]
            decrypted = vigenere.decrypt(reversed_cipher, key)
            score = self._score_decryption(decrypted, ciphertext)
            results['reversed_input'] = (decrypted, score)
        except:
            results['reversed_input'] = ("", 0.0)
        
        # 4. With text reversal (post-processing)
        try:
            decrypted = vigenere.decrypt(ciphertext, key)[::-1]
            score = self._score_decryption(decrypted, ciphertext)
            results['reversed_output'] = (decrypted, score)
        except:
            results['reversed_output'] = ("", 0.0)
        
        return results

    def _autokey_decrypt(self, ciphertext: str, key: str) -> str:
        """Decrypt using auto-key Vigenère cipher"""
        alphabet = string.ascii_uppercase
        decrypted = []
        extended_key = key
        
        for i, char in enumerate(ciphertext):
            if char in alphabet:
                if i >= len(extended_key):
                    # Use previous decrypted character as key
                    if decrypted:
                        extended_key += decrypted[-1]
                    else:
                        extended_key += 'A'  # Default
                
                key_char = extended_key[i % len(extended_key)]
                shift = alphabet.index(key_char)
                char_index = alphabet.index(char)
                decrypted_char = alphabet[(char_index - shift) % 26]
                decrypted.append(decrypted_char)
            else:
                decrypted.append(char)
        
        return ''.join(decrypted)

    def test_transposition_combinations(self, ciphertext: str, key: str) -> Dict[str, Tuple[str, float]]:
        """Test combinations with columnar transposition"""
        results = {}
        
        from ciphers import VigenereCipher
        vigenere = VigenereCipher()
        
        # Test different column counts for transposition
        for cols in range(2, min(12, len(ciphertext) // 4)):
            try:
                # Pre-transposition: transpose then decrypt
                transposed = self._columnar_transpose_decrypt(ciphertext, cols)
                decrypted = vigenere.decrypt(transposed, key)
                score = self._score_decryption(decrypted, ciphertext)
                results[f'pre_transpose_{cols}'] = (decrypted, score)
                
                # Post-transposition: decrypt then transpose
                decrypted_first = vigenere.decrypt(ciphertext, key)
                final = self._columnar_transpose_decrypt(decrypted_first, cols)
                score = self._score_decryption(final, ciphertext)
                results[f'post_transpose_{cols}'] = (final, score)
                
            except:
                continue
        
        return results

    def _columnar_transpose_decrypt(self, text: str, columns: int) -> str:
        """Simple columnar transposition decryption"""
        if columns <= 1 or len(text) <= columns:
            return text
        
        rows = len(text) // columns
        if len(text) % columns != 0:
            rows += 1
        
        # Create grid
        grid = [['' for _ in range(columns)] for _ in range(rows)]
        
        # Fill grid column by column
        idx = 0
        for col in range(columns):
            for row in range(rows):
                if idx < len(text):
                    grid[row][col] = text[idx]
                    idx += 1
        
        # Read row by row
        result = []
        for row in range(rows):
            for col in range(columns):
                if grid[row][col]:
                    result.append(grid[row][col])
        
        return ''.join(result)

    def _score_decryption(self, decrypted_text: str, original_cipher: str) -> float:
        """Score decrypted text based on multiple criteria"""
        if not decrypted_text:
            return 0.0
        
        score = 0.0
        
        # 1. Known plaintext validation (highest weight)
        known_plaintext_score = self._check_known_plaintext(decrypted_text)
        score += known_plaintext_score * 10.0
        
        # 2. English frequency analysis
        frequency_score = self._analyze_english_frequency(decrypted_text)
        score += frequency_score * 3.0
        
        # 3. Index of Coincidence
        ic_score = self._calculate_ic_score(decrypted_text)
        score += ic_score * 2.0
        
        # 4. Common English patterns
        pattern_score = self._check_english_patterns(decrypted_text)
        score += pattern_score * 1.5
        
        # 5. Fuzzy matching for potential typos
        fuzzy_score = self._fuzzy_known_plaintext_check(decrypted_text)
        score += fuzzy_score * 5.0
        
        return score

    def _check_known_plaintext(self, text: str) -> float:
        """Check for exact known plaintext matches"""
        score = 0.0
        text_upper = text.upper()
        
        for plaintext, start, end, variant in self.known_plaintext_k4:
            # Check exact position
            if start < len(text_upper) and end <= len(text_upper):
                segment = text_upper[start:end+1]
                if segment == plaintext or segment == variant:
                    score += 1.0
            
            # Check anywhere in text
            if plaintext in text_upper or variant in text_upper:
                score += 0.5
        
        return score / len(self.known_plaintext_k4)

    def _fuzzy_known_plaintext_check(self, text: str) -> float:
        """Fuzzy matching for known plaintext with potential typos"""
        score = 0.0
        text_upper = text.upper()
        
        for plaintext, start, end, variant in self.known_plaintext_k4:
            # Check with single character differences
            for i in range(len(text_upper) - len(plaintext) + 1):
                segment = text_upper[i:i+len(plaintext)]
                differences = sum(1 for a, b in zip(segment, plaintext) if a != b)
                if differences <= 1:  # Allow 1 character difference
                    score += 0.8 - (differences * 0.3)
        
        return score / len(self.known_plaintext_k4)

    def _analyze_english_frequency(self, text: str) -> float:
        """Score based on English letter frequency"""
        if not text:
            return 0.0
        
        # Standard English frequency percentages
        english_freq = {
            'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
            'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25,
            'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36,
            'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29,
            'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07
        }
        
        # Count letters in text
        letter_count = Counter(char for char in text.upper() if char.isalpha())
        total_letters = sum(letter_count.values())
        
        if total_letters == 0:
            return 0.0
        
        # Calculate chi-squared statistic
        chi_squared = 0.0
        for letter in string.ascii_uppercase:
            observed = letter_count.get(letter, 0)
            expected = (english_freq.get(letter, 0) / 100) * total_letters
            if expected > 0:
                chi_squared += ((observed - expected) ** 2) / expected
        
        # Convert to score (lower chi-squared is better)
        return max(0, 1 - (chi_squared / 1000))

    def _calculate_ic_score(self, text: str) -> float:
        """Calculate Index of Coincidence score"""
        if len(text) < 2:
            return 0.0
        
        # Count letter frequencies
        letter_count = Counter(char for char in text.upper() if char.isalpha())
        total_letters = sum(letter_count.values())
        
        if total_letters < 2:
            return 0.0
        
        # Calculate IC
        ic = sum(count * (count - 1) for count in letter_count.values())
        ic /= (total_letters * (total_letters - 1))
        
        # English IC is approximately 0.067
        english_ic = 0.067
        score = 1 - abs(ic - english_ic) / english_ic
        return max(0, score)

    def _check_english_patterns(self, text: str) -> float:
        """Check for common English language patterns"""
        if not text:
            return 0.0
        
        score = 0.0
        text_upper = text.upper()
        
        # Common English patterns
        patterns = [
            r'THE', r'AND', r'ING', r'ION', r'TIO', r'ENT', r'FOR',
            r'ARE', r'HER', r'HIS', r'BUT', r'NOT', r'WITH', r'HAD',
            r'THAT', r'THIS', r'HAVE', r'FROM', r'THEY', r'KNOW'
        ]
        
        total_patterns = len(patterns)
        found_patterns = 0
        
        for pattern in patterns:
            if re.search(pattern, text_upper):
                found_patterns += 1
        
        score = found_patterns / total_patterns
        return score

    def parallel_key_testing(self, ciphertext: str, max_keys: int = 1000, 
                           max_workers: int = None, custom_keys: List[str] = None) -> List[Tuple[str, str, str, float]]:
        """Test multiple keys in parallel and return best results"""
        if max_workers is None:
            max_workers = min(4, multiprocessing.cpu_count())  # Limit to 4 workers for stability
        
        results = []
        key_generator = self.generate_key_candidates(custom_keys=custom_keys)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit initial batch of tasks
            future_to_key = {}
            keys_tested = 0
            
            for key in key_generator:
                if keys_tested >= max_keys:
                    break
                
                future = executor.submit(self._test_single_key, ciphertext, key)
                future_to_key[future] = key
                keys_tested += 1
            
            # Process completed tasks
            for future in as_completed(future_to_key):
                key = future_to_key[future]
                try:
                    key_results = future.result()
                    results.extend(key_results)
                except Exception as e:
                    print(f"Error testing key {key}: {e}")
        
        # Sort by score and return best results
        results.sort(key=lambda x: x[3], reverse=True)
        return results[:50]  # Return top 50 results

    def _test_single_key(self, ciphertext: str, key: str) -> List[Tuple[str, str, str, float]]:
        """Test a single key with all variants"""
        results = []
        
        # Test Vigenère variants
        vigenere_results = self.test_vigenere_variants(ciphertext, key)
        for variant, (decrypted, score) in vigenere_results.items():
            if score > 0:
                results.append((key, variant, decrypted, score))
        
        # Test transposition combinations for promising keys
        if any(score > 2.0 for _, score in vigenere_results.values()):
            transposition_results = self.test_transposition_combinations(ciphertext, key)
            for variant, (decrypted, score) in transposition_results.items():
                if score > 0:
                    results.append((key, f"vigenere+{variant}", decrypted, score))
        
        return results

    def comprehensive_attack(self, ciphertext: str, max_keys: int = 5000, 
                           custom_keys: List[str] = None) -> Dict:
        """Perform comprehensive attack on ciphertext"""
        print(f"Starting comprehensive attack on {len(ciphertext)} character cipher...")
        if custom_keys:
            print(f"Priority testing with custom keys: {', '.join(custom_keys)}")
        start_time = time.time()
        
        # Parallel key testing
        results = self.parallel_key_testing(ciphertext, max_keys, custom_keys=custom_keys)
        
        # Filter and analyze results
        significant_results = [r for r in results if r[3] > 1.0]
        
        analysis = {
            'total_keys_tested': max_keys,
            'total_results': len(results),
            'significant_results': len(significant_results),
            'best_results': results[:10],
            'execution_time': time.time() - start_time,
            'cipher_length': len(ciphertext),
            'custom_keys_used': custom_keys or []
        }
        
        # Additional analysis for best results
        if results:
            best_result = results[0]
            analysis['best_key'] = best_result[0]
            analysis['best_method'] = best_result[1]
            analysis['best_decryption'] = best_result[2]
            analysis['best_score'] = best_result[3]
            
            # Check for known plaintext in best result
            known_plaintext_found = self._check_known_plaintext(best_result[2])
            analysis['known_plaintext_matches'] = known_plaintext_found
        
        print(f"Attack completed in {analysis['execution_time']:.2f} seconds")
        print(f"Found {len(significant_results)} significant results out of {max_keys} keys tested")
        
        return analysis
    
    def test_specific_keys(self, ciphertext: str, keys: List[str]) -> Dict:
        """Test specific keys with detailed analysis"""
        print(f"Testing specific keys: {', '.join(keys)}")
        start_time = time.time()
        
        detailed_results = {}
        
        for key in keys:
            print(f"Testing key: {key}")
            key_results = {}
            
            # Test all variants for this key
            vigenere_results = self.test_vigenere_variants(ciphertext, key)
            key_results['vigenere_variants'] = vigenere_results
            
            # Test transposition combinations
            transposition_results = self.test_transposition_combinations(ciphertext, key)
            key_results['transposition_variants'] = transposition_results
            
            # Find best result for this key
            all_variants = {**vigenere_results, **transposition_results}
            best_variant = max(all_variants.items(), key=lambda x: x[1][1])
            key_results['best_variant'] = {
                'method': best_variant[0],
                'decryption': best_variant[1][0],
                'score': best_variant[1][1]
            }
            
            detailed_results[key] = key_results
        
        analysis = {
            'keys_tested': keys,
            'detailed_results': detailed_results,
            'execution_time': time.time() - start_time
        }
        
        # Find overall best result
        best_overall = None
        best_score = 0
        
        for key, results in detailed_results.items():
            if results['best_variant']['score'] > best_score:
                best_score = results['best_variant']['score']
                best_overall = {
                    'key': key,
                    'method': results['best_variant']['method'],
                    'decryption': results['best_variant']['decryption'],
                    'score': best_score
                }
        
        analysis['best_overall'] = best_overall
        
        print(f"Specific key testing completed in {analysis['execution_time']:.2f} seconds")
        return analysis